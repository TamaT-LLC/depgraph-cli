package worker

import (
	"fmt"
	"go/ast"
	"go/types"
)

type goSemanticReferenceTarget struct {
	nodeID     string
	resolver   string
	status     string
	precision  string
	reason     string
	objectKind string
}

// emitValueReferences records value-bearing go/types uses after declarations,
// selections, and generic instances have established their canonical nodes.
// Calls and type uses own their terminal identifiers, so those occurrences are
// deliberately excluded here instead of being represented twice.
func (p *goSemanticPackage) emitValueReferences() {
	callOwned := p.callOwnedIdentifiers()
	for _, file := range p.files {
		ast.Inspect(file.Syntax, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok || identifier.Name == "_" || callOwned[identifier] {
				return true
			}
			object := p.typed.TypesInfo.Uses[identifier]
			if !goSemanticIsValueObject(object) {
				return true
			}
			ownerID := p.nearestOwner(identifier)
			if ownerID == "" {
				p.extractor.fail("go_semantic_owner", file.Path, fmt.Sprintf("value reference %q has no semantic symbol owner", identifier.Name))
				return true
			}
			owner, exists := p.extractor.state.nodes[ownerID]
			if !exists {
				p.extractor.fail("go_semantic_owner", file.Path, fmt.Sprintf("value reference %q has an unknown semantic owner", identifier.Name))
				return true
			}
			// A value can legitimately occur inside a type declaration (for
			// example, a named constant used as an array length). The strict
			// value-reference contract requires a symbol source, so leave these
			// occurrences unrepresented without degrading semantic completeness.
			if owner.Kind != "symbol" {
				return true
			}

			selection, occurrenceKind := p.referenceSelection(identifier)
			target := p.valueReferenceTarget(identifier, object, selection)
			if target.nodeID == "" {
				return true
			}
			specifier := target.resolver
			if specifier == "" {
				specifier = identifier.Name
			}
			properties := map[string]any{
				"object_kind":     target.objectKind,
				"occurrence_kind": occurrenceKind,
			}
			if target.resolver != "" {
				properties["resolver_identity"] = target.resolver
			}
			evidence := p.evidence(file, identifier, specifier, properties)
			if target.status == "unresolved" {
				p.extractor.failValueReference(file.Path, specifier, target.reason, evidence)
			}
			p.extractor.addValueReference(
				owner.ID,
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

func (p *goSemanticPackage) callOwnedIdentifiers() map[*ast.Ident]bool {
	owned := map[*ast.Ident]bool{}
	for _, file := range p.files {
		ast.Inspect(file.Syntax, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if identifier := goSemanticCallIdentifier(goSemanticCallBase(call.Fun)); identifier != nil {
				owned[identifier] = true
			}
			return true
		})
	}
	return owned
}

func goSemanticIsValueObject(object types.Object) bool {
	switch object.(type) {
	case *types.Var, *types.Const, *types.Func:
		return true
	default:
		return false
	}
}

func (p *goSemanticPackage) referenceSelection(identifier *ast.Ident) (*types.Selection, string) {
	selector, ok := p.parents[identifier].(*ast.SelectorExpr)
	if !ok || selector.Sel != identifier {
		return nil, "identifier"
	}
	selection := p.typed.TypesInfo.Selections[selector]
	if selection == nil {
		return nil, "qualified_identifier"
	}
	switch selection.Kind() {
	case types.FieldVal:
		return selection, "field_selection"
	case types.MethodVal:
		return selection, "method_value"
	case types.MethodExpr:
		return selection, "method_expression"
	default:
		return selection, "selection"
	}
}

func (p *goSemanticPackage) valueReferenceTarget(identifier *ast.Ident, object types.Object, selection *types.Selection) goSemanticReferenceTarget {
	objectKind := p.valueReferenceObjectKind(object, identifier)
	if nodeID := p.instanceNodes[identifier]; nodeID != "" {
		if node := p.extractor.state.nodes[nodeID]; node.Kind == "symbol" {
			return goSemanticReferenceTarget{
				nodeID: nodeID, resolver: p.extractor.nodeResolvers[nodeID],
				status: "resolved", precision: "exact", objectKind: objectKind,
			}
		} else if node.Kind == "external_system" {
			return goSemanticReferenceTarget{
				nodeID: nodeID, resolver: p.extractor.nodeResolvers[nodeID],
				status: "external", precision: "exact", objectKind: objectKind,
			}
		}
	}
	if nodeID := p.objectNodes[object]; nodeID != "" {
		return goSemanticReferenceTarget{
			nodeID: nodeID, resolver: p.extractor.nodeResolvers[nodeID],
			status: "resolved", precision: "exact", objectKind: objectKind,
		}
	}

	resolver := p.valueReferenceResolver(identifier, object, selection)
	packagePath := ""
	if object != nil && object.Pkg() != nil {
		packagePath = object.Pkg().Path()
	}
	if resolver != "" {
		if nodeID := p.visibleSymbolNode(resolver, packagePath); nodeID != "" {
			canonicalResolver := p.extractor.nodeResolvers[nodeID]
			if canonicalResolver == "" {
				canonicalResolver = resolver
			}
			return goSemanticReferenceTarget{
				nodeID: nodeID, resolver: canonicalResolver,
				status: "resolved", precision: "exact", objectKind: objectKind,
			}
		}
		if packagePath != "" {
			nodeID := p.extractor.ensureExternalSymbol(resolver, object.Name(), objectKind)
			return goSemanticReferenceTarget{
				nodeID: nodeID, resolver: resolver,
				status: "external", precision: "exact", objectKind: objectKind,
			}
		}
	}
	return goSemanticReferenceTarget{
		nodeID: p.extractor.state.ensureUnknownNode(), resolver: resolver,
		status: "unresolved", precision: "heuristic", reason: "object_identity_unavailable",
		objectKind: objectKind,
	}
}

func (p *goSemanticPackage) valueReferenceResolver(identifier *ast.Ident, object types.Object, selection *types.Selection) string {
	if function, ok := object.(*types.Func); ok {
		return goSemanticFunctionResolver(function)
	}
	if variable, ok := object.(*types.Var); ok && variable.IsField() {
		if resolver := goSemanticFieldSelectionResolver(selection); resolver != "" {
			return resolver
		}
		if resolver := p.fieldKeyResolver(identifier); resolver != "" {
			return resolver
		}
	}
	if object != nil && object.Pkg() != nil && object.Parent() == object.Pkg().Scope() {
		return object.Pkg().Path() + "." + object.Name()
	}
	return ""
}

func (p *goSemanticPackage) fieldKeyResolver(identifier *ast.Ident) string {
	keyValue, ok := p.parents[identifier].(*ast.KeyValueExpr)
	if !ok || keyValue.Key != identifier {
		return ""
	}
	composite, ok := p.parents[keyValue].(*ast.CompositeLit)
	if !ok {
		return ""
	}
	resolver := goSemanticNamedTypeResolver(p.typed.TypesInfo.TypeOf(composite))
	if resolver == "" {
		return ""
	}
	return resolver + "." + identifier.Name
}

func goSemanticFieldSelectionResolver(selection *types.Selection) string {
	if selection == nil || selection.Obj() == nil || len(selection.Index()) == 0 {
		return ""
	}
	current := selection.Recv()
	ownerResolver := ""
	for depth, index := range selection.Index() {
		if resolver := goSemanticNamedTypeResolver(current); resolver != "" {
			ownerResolver = resolver
		}
		underlying := goSemanticUnaliasAndDereference(current)
		if named, ok := underlying.(*types.Named); ok {
			underlying = named.Underlying()
		}
		structure, ok := underlying.(*types.Struct)
		if !ok || index < 0 || index >= structure.NumFields() {
			return ""
		}
		field := structure.Field(index)
		if depth == len(selection.Index())-1 {
			if ownerResolver == "" {
				return ""
			}
			return ownerResolver + "." + field.Name()
		}
		current = field.Type()
	}
	return ""
}

func goSemanticNamedTypeResolver(value types.Type) string {
	value = goSemanticUnaliasAndDereference(value)
	named, ok := value.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return ""
	}
	return named.Obj().Pkg().Path() + "." + named.Obj().Name()
}

func goSemanticUnaliasAndDereference(value types.Type) types.Type {
	for value != nil {
		switch typed := value.(type) {
		case *types.Alias:
			value = types.Unalias(typed)
		case *types.Pointer:
			value = typed.Elem()
		default:
			return value
		}
	}
	return nil
}

func (p *goSemanticPackage) valueReferenceObjectKind(object types.Object, identifier *ast.Ident) string {
	if function, ok := object.(*types.Func); ok {
		if signature, ok := function.Type().(*types.Signature); ok && signature.Recv() != nil {
			return "method"
		}
		return "function"
	}
	if kind := p.symbolKind(object, identifier); kind != "" {
		return kind
	}
	return "value"
}

func (e *goSemanticExtractor) addValueReference(
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
		"condition": condition, "kind": "value_reference", "path": primary.Path,
		"profile_id": e.state.profile.ID, "source": sourceID,
		"span": goSemanticSpan(primary),
	}
	site := Site{
		ID: stableIDFromValue("site", siteIdentity), Source: sourceID, Kind: "value_reference",
		Specifier: specifier, ResolutionStatus: status, TargetIDs: []string{targetID},
		ProfileID: e.state.profile.ID, Condition: condition, Precision: precision,
		Evidence: append([]Evidence(nil), evidence...), Reason: reason,
	}
	if old, ok := e.state.sites[site.ID]; ok {
		if !goSemanticEqual(old, site) {
			e.fail("go_semantic_identity_conflict", primary.Path, "conflicting semantic value-reference site "+site.ID)
		}
		return
	}
	e.state.sites[site.ID] = site
	edgeIdentity := map[string]any{"kind": "references", "site_id": site.ID, "target": targetID}
	edge := Edge{
		ID: stableIDFromValue("edge", edgeIdentity), Source: sourceID, Target: targetID,
		Kind: "references", SiteID: site.ID, Phase: "semantic", Environment: "any",
		ResolutionStatus: status, ProfileID: e.state.profile.ID, Condition: condition,
		Precision: precision, Generated: generated, Evidence: append([]Evidence(nil), evidence...),
	}
	if old, ok := e.state.edges[edge.ID]; ok && !goSemanticEqual(old, edge) {
		e.fail("go_semantic_identity_conflict", primary.Path, "conflicting semantic references edge "+edge.ID)
		return
	}
	e.state.edges[edge.ID] = edge
}

func (e *goSemanticExtractor) failValueReference(path, specifier, reason string, evidence []Evidence) {
	e.complete = false
	if len(evidence) == 0 {
		return
	}
	primary := evidence[0]
	identity := map[string]any{
		"code": "go_value_reference_unresolved", "path": path,
		"profile_id": e.state.profile.ID, "reason": reason, "span": goSemanticSpan(primary),
	}
	diagnostic := Diagnostic{
		ID: stableIDFromValue("diagnostic", identity), Code: "go_value_reference_unresolved",
		Severity: "warning", Message: fmt.Sprintf("value reference target %q remains unresolved: %s", specifier, reason),
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
