package worker

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"strings"
)

type goSemanticSymbolOrigin struct {
	moduleDir   string
	packagePath string
}

type goSemanticCallTarget struct {
	nodeID    string
	resolver  string
	status    string
	precision string
	reason    string
	dispatch  string
	callKind  string
}

func (p *goSemanticPackage) emitCalls() {
	for _, file := range p.files {
		ast.Inspect(file.Syntax, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if value, ok := p.typed.TypesInfo.Types[call.Fun]; ok && value.IsType() {
				// Go represents conversions with CallExpr too. They are type uses,
				// not calls, even when the converted type has function syntax.
				return true
			}
			callerID := p.callOwner(file, call)
			if callerID == "" || p.extractor.state.nodes[callerID].Kind != "symbol" {
				return true
			}
			target, emit := p.callTarget(call.Fun)
			if !emit || target.nodeID == "" {
				return true
			}
			specifier := target.resolver
			if specifier == "" {
				specifier = goSemanticCallName(call.Fun)
			}
			properties := map[string]any{"dispatch": target.dispatch}
			if target.callKind != "" {
				properties["call_kind"] = target.callKind
			}
			if target.resolver != "" {
				properties["resolver_identity"] = target.resolver
			}
			evidence := p.evidence(file, call, specifier, properties)
			if target.status == "unresolved" {
				p.extractor.failCall(file.Path, specifier, target.reason, evidence)
			}
			p.extractor.addCall(
				callerID,
				target.nodeID,
				specifier,
				target.status,
				target.precision,
				target.reason,
				p.condition(file.Path),
				evidence,
				p.generated(file.Path),
			)
			return true
		})
	}
}

func (p *goSemanticPackage) callOwner(file goTypedFile, call *ast.CallExpr) string {
	for current := p.parents[call]; current != nil; current = p.parents[current] {
		switch typed := current.(type) {
		case *ast.FuncLit:
			return p.owners[typed]
		case *ast.FuncDecl:
			return p.owners[typed]
		case *ast.ValueSpec:
			if !p.packageValueSpec(typed) {
				continue
			}
			if nodeID := p.callInitializers[typed]; nodeID != "" {
				return nodeID
			}
			nodeID := p.ensurePackageInitializer(file, typed, "package initialization")
			p.callInitializers[typed] = nodeID
			return nodeID
		}
	}
	return ""
}

func (p *goSemanticPackage) packageValueSpec(spec *ast.ValueSpec) bool {
	for current := p.parents[spec]; current != nil; current = p.parents[current] {
		switch current.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			return false
		case *ast.File:
			return true
		}
	}
	return false
}

func (p *goSemanticPackage) callTarget(expression ast.Expr) (goSemanticCallTarget, bool) {
	base := goSemanticCallBase(expression)
	if literal, ok := base.(*ast.FuncLit); ok {
		nodeID := p.owners[literal]
		if nodeID == "" {
			return goSemanticCallTarget{}, false
		}
		return goSemanticCallTarget{
			nodeID: nodeID, resolver: nodeID, status: "resolved", precision: "exact", dispatch: "static", callKind: "closure",
		}, true
	}

	identifier := goSemanticCallIdentifier(base)
	if identifier == nil {
		return p.unresolvedCall(goSemanticCallName(base), "function_value_dispatch", "function_value")
	}
	if instanceID := p.instanceNodes[identifier]; instanceID != "" {
		return p.callTargetForNode(instanceID, "generic")
	}

	if selector, ok := base.(*ast.SelectorExpr); ok {
		if selection := p.typed.TypesInfo.Selections[selector]; selection != nil {
			function, ok := selection.Obj().(*types.Func)
			if !ok {
				return p.unresolvedCall(goSemanticCallName(base), "function_value_dispatch", "function_value")
			}
			if goSemanticSelectionIsDynamic(selection, function) {
				return p.unresolvedCall(goSemanticFunctionResolver(function), "interface_dispatch", "interface")
			}
			return p.callTargetForFunction(function, "method")
		}
	}

	object := p.typed.TypesInfo.Uses[identifier]
	switch typed := object.(type) {
	case *types.Func:
		callKind := "function"
		if signature, ok := typed.Type().(*types.Signature); ok && signature.Recv() != nil {
			callKind = "method"
		}
		return p.callTargetForFunction(typed, callKind)
	case *types.Builtin:
		resolver := goSemanticBuiltinResolver(typed)
		nodeID := p.extractor.ensureExternalSymbol(resolver, typed.Name(), "builtin")
		if nodeID == "" {
			return goSemanticCallTarget{}, false
		}
		return goSemanticCallTarget{
			nodeID: nodeID, resolver: resolver, status: "external", precision: "exact", dispatch: "static", callKind: "builtin",
		}, true
	case nil:
		resolver := goSemanticCallName(base)
		if resolver == "" {
			return goSemanticCallTarget{}, false
		}
		return goSemanticCallTarget{
			nodeID: p.extractor.state.ensureUnknownNode(), resolver: resolver,
			status: "unresolved", precision: "heuristic", reason: "callee_not_resolved", dispatch: "unresolved",
		}, true
	default:
		return p.unresolvedCall(goSemanticCallName(base), "function_value_dispatch", "function_value")
	}
}

func (p *goSemanticPackage) unresolvedCall(resolver, reason, dispatch string) (goSemanticCallTarget, bool) {
	if resolver == "" {
		resolver = "dynamic call"
	}
	return goSemanticCallTarget{
		nodeID: p.extractor.state.ensureUnknownNode(), resolver: resolver,
		status: "unresolved", precision: "heuristic", reason: reason, dispatch: dispatch,
	}, true
}

func (p *goSemanticPackage) callTargetForFunction(function *types.Func, callKind string) (goSemanticCallTarget, bool) {
	resolver := goSemanticFunctionResolver(function)
	if goSemanticReflectiveCall(resolver) {
		return p.unresolvedCall(resolver, "reflection_dispatch", "reflection")
	}
	packagePath := goSemanticFunctionPackagePath(function)
	nodeID := p.objectNodes[function]
	if nodeID != "" && !p.symbolNodeVisible(nodeID, packagePath) {
		nodeID = ""
	}
	if nodeID == "" {
		nodeID = p.visibleSymbolNode(resolver, packagePath)
	}
	if nodeID != "" {
		target, ok := p.callTargetForNode(nodeID, callKind)
		if ok && target.resolver == "" {
			target.resolver = resolver
		}
		return target, ok
	}
	nodeID = p.extractor.ensureExternalSymbol(resolver, function.Name(), goSemanticExternalSymbolKind(function))
	if nodeID == "" {
		return goSemanticCallTarget{}, false
	}
	return goSemanticCallTarget{
		nodeID: nodeID, resolver: resolver, status: "external", precision: "exact", dispatch: "static", callKind: callKind,
	}, true
}

func (e *goSemanticExtractor) registerSymbolOrigin(nodeID string, pkg goTypedPackage) {
	origin := goSemanticSymbolOrigin{
		moduleDir:   filepath.Clean(filepath.Join(e.state.root, filepath.FromSlash(pkg.ModuleRelativeDir))),
		packagePath: pkg.PkgPath,
	}
	for _, existing := range e.symbolOrigins[nodeID] {
		if existing == origin {
			return
		}
	}
	e.symbolOrigins[nodeID] = append(e.symbolOrigins[nodeID], origin)
}

func (p *goSemanticPackage) visibleSymbolNode(resolver, importPath string) string {
	resolvers := []string{resolver}
	sourceDir := p.moduleDir()
	if _, rewritten, replaced := p.extractor.state.moduleResolution.replacementImport(sourceDir, importPath); replaced {
		if rewrittenResolver := goSemanticRewriteResolver(resolver, importPath, rewritten); rewrittenResolver != resolver {
			resolvers = append(resolvers, rewrittenResolver)
		}
	}
	for _, candidate := range resolvers {
		nodeID := p.extractor.symbolNodesByResolver[candidate]
		if nodeID != "" && p.symbolNodeVisible(nodeID, importPath) {
			return nodeID
		}
	}
	return ""
}

func (p *goSemanticPackage) symbolNodeVisible(nodeID, importPath string) bool {
	if importPath == "" {
		return false
	}
	sourceDir := p.moduleDir()
	targetDir, rewritten, replaced := p.extractor.state.moduleResolution.replacementImport(sourceDir, importPath)
	for _, origin := range p.extractor.symbolOrigins[nodeID] {
		if origin.packagePath == importPath && p.extractor.state.moduleResolution.directlyVisible(sourceDir, origin.moduleDir) {
			return true
		}
		if replaced && origin.moduleDir == targetDir && origin.packagePath == rewritten {
			return true
		}
	}
	return false
}

func (p *goSemanticPackage) moduleDir() string {
	return filepath.Clean(filepath.Join(p.extractor.state.root, filepath.FromSlash(p.typed.ModuleRelativeDir)))
}

func goSemanticRewriteResolver(resolver, oldPackagePath, newPackagePath string) string {
	prefix := oldPackagePath + "."
	if !strings.HasPrefix(resolver, prefix) {
		return resolver
	}
	return newPackagePath + strings.TrimPrefix(resolver, oldPackagePath)
}

func (p *goSemanticPackage) callTargetForNode(nodeID, callKind string) (goSemanticCallTarget, bool) {
	node, ok := p.extractor.state.nodes[nodeID]
	if !ok {
		return goSemanticCallTarget{}, false
	}
	resolver := p.extractor.nodeResolvers[nodeID]
	if resolver == "" {
		resolver, _ = node.Properties["resolver_identity"].(string)
	}
	switch node.Kind {
	case "symbol":
		return goSemanticCallTarget{
			nodeID: nodeID, resolver: resolver, status: "resolved", precision: "exact", dispatch: "static", callKind: callKind,
		}, true
	case "external_system":
		return goSemanticCallTarget{
			nodeID: nodeID, resolver: resolver, status: "external", precision: "exact", dispatch: "static", callKind: callKind,
		}, true
	default:
		return goSemanticCallTarget{}, false
	}
}

func goSemanticCallBase(expression ast.Expr) ast.Expr {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.IndexExpr:
			expression = typed.X
		case *ast.IndexListExpr:
			expression = typed.X
		default:
			return expression
		}
	}
}

func goSemanticCallIdentifier(expression ast.Expr) *ast.Ident {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed
	case *ast.SelectorExpr:
		return typed.Sel
	default:
		return nil
	}
}

func goSemanticCallName(expression ast.Expr) string {
	base := goSemanticCallBase(expression)
	switch typed := base.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		if prefix := goSemanticCallName(typed.X); prefix != "" {
			return prefix + "." + typed.Sel.Name
		}
		return typed.Sel.Name
	case *ast.StarExpr:
		return goSemanticCallName(typed.X)
	default:
		return ""
	}
}

func goSemanticSelectionIsDynamic(selection *types.Selection, function *types.Func) bool {
	if selection == nil || function == nil {
		return true
	}
	if goSemanticDynamicReceiver(selection.Recv()) {
		return true
	}
	signature, _ := function.Type().(*types.Signature)
	return signature != nil && signature.Recv() != nil && goSemanticDynamicReceiver(signature.Recv().Type())
}

func goSemanticReflectiveCall(resolver string) bool {
	return resolver == "reflect.(Value).Call" || resolver == "reflect.(Value).CallSlice"
}

func goSemanticFunctionPackagePath(function *types.Func) string {
	if function == nil || function.Pkg() == nil {
		return ""
	}
	return function.Pkg().Path()
}

func goSemanticDynamicReceiver(value types.Type) bool {
	switch typed := value.(type) {
	case *types.Pointer:
		return goSemanticDynamicReceiver(typed.Elem())
	case *types.Alias:
		return goSemanticDynamicReceiver(types.Unalias(typed))
	case *types.TypeParam:
		return true
	case *types.Interface:
		return true
	case *types.Named:
		_, dynamic := typed.Underlying().(*types.Interface)
		return dynamic
	default:
		return false
	}
}

func goSemanticBuiltinResolver(builtin *types.Builtin) string {
	if builtin != nil && builtin.Pkg() != nil {
		return builtin.Pkg().Path() + "." + builtin.Name()
	}
	if builtin == nil {
		return "builtin.unknown"
	}
	return "builtin." + builtin.Name()
}

func goSemanticExternalSymbolKind(function *types.Func) string {
	if signature, ok := function.Type().(*types.Signature); ok && signature.Recv() != nil {
		return "method"
	}
	return "function"
}

func (e *goSemanticExtractor) ensureExternalSymbol(resolver, displayName, symbolKind string) string {
	identity := map[string]any{
		"language": "go", "resolver_identity": resolver,
		"target_kind": "symbol", "symbol_kind": symbolKind,
	}
	targetID := stableIDFromValue("external_system", identity)
	nodeValue := Node{
		ID: targetID, Kind: "external_system", Locator: "go-symbol:" + resolver,
		DisplayName: displayName,
		Properties: map[string]any{
			"language": "go", "external": true, "target_kind": "symbol",
			"symbol_kind": symbolKind, "resolver_identity": resolver,
		},
	}
	if !e.addNode(nodeValue, "") {
		return ""
	}
	e.nodeResolvers[targetID] = resolver
	return targetID
}

func (e *goSemanticExtractor) addCall(
	sourceID, targetID, specifier, status, precision, reason string,
	condition Condition,
	evidence []Evidence,
	generated bool,
) {
	if sourceID == "" || targetID == "" || len(evidence) == 0 {
		return
	}
	condition = canonicalCondition(condition)
	primary := evidence[0]
	siteIdentity := map[string]any{
		"condition": condition, "kind": "call", "path": primary.Path,
		"profile_id": e.state.profile.ID, "source": sourceID,
		"span": goSemanticSpan(primary),
	}
	site := Site{
		ID: stableIDFromValue("site", siteIdentity), Source: sourceID, Kind: "call",
		Specifier: specifier, ResolutionStatus: status, TargetIDs: []string{targetID},
		ProfileID: e.state.profile.ID, Condition: condition, Precision: precision,
		Evidence: append([]Evidence(nil), evidence...), Reason: reason,
	}
	if old, ok := e.state.sites[site.ID]; ok {
		if !goSemanticEqual(old, site) {
			e.fail("go_semantic_identity_conflict", primary.Path, "conflicting semantic call site "+site.ID)
		}
		return
	}
	e.state.sites[site.ID] = site
	edgeIdentity := map[string]any{"kind": "calls", "site_id": site.ID, "target": targetID}
	edge := Edge{
		ID: stableIDFromValue("edge", edgeIdentity), Source: sourceID, Target: targetID,
		Kind: "calls", SiteID: site.ID, Phase: "semantic", Environment: "any",
		ResolutionStatus: status, ProfileID: e.state.profile.ID, Condition: condition,
		Precision: precision, Generated: generated, Evidence: append([]Evidence(nil), evidence...),
	}
	if old, ok := e.state.edges[edge.ID]; ok && !goSemanticEqual(old, edge) {
		e.fail("go_semantic_identity_conflict", primary.Path, "conflicting semantic calls edge "+edge.ID)
		return
	}
	e.state.edges[edge.ID] = edge
}

func (e *goSemanticExtractor) failCall(path, specifier, reason string, evidence []Evidence) {
	if reason == "callee_not_resolved" {
		e.complete = false
	}
	if len(evidence) == 0 {
		return
	}
	primary := evidence[0]
	identity := map[string]any{
		"code": "go_call_unresolved", "path": path,
		"profile_id": e.state.profile.ID, "reason": reason, "span": goSemanticSpan(primary),
	}
	diagnostic := Diagnostic{
		ID: stableIDFromValue("diagnostic", identity), Code: "go_call_unresolved",
		Severity: "warning", Message: fmt.Sprintf("call target %q remains unresolved: %s", specifier, reason),
		ProfileID: e.state.profile.ID, Path: path,
		StartLine: primary.StartLine, StartColumn: primary.StartColumn,
		EndLine: primary.EndLine, EndColumn: primary.EndColumn,
		Evidence:   append([]Evidence(nil), evidence...),
		Properties: map[string]any{"reason": reason}, Recoverable: true,
	}
	if e.diagnosticIDs[diagnostic.ID] {
		return
	}
	e.diagnosticIDs[diagnostic.ID] = true
	e.state.diagnostics = append(e.state.diagnostics, diagnostic)
}
