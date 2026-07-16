package worker

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/types"
	"sort"
	"strconv"
	"strings"
)

// goSemanticExtractor translates the retained go/packages type universes into
// the protocol's language-neutral symbol/type graph. It deliberately walks AST
// nodes instead of ranging over go/types maps: map iteration order is unstable,
// while source order plus canonical IDs gives deterministic output and safely
// coalesces the normal and internal-test package universes.
type goSemanticExtractor struct {
	state                 *scannerState
	sources               map[string]*sourceFile
	contexts              []*goSemanticPackage
	typeNodesByResolver   map[string]string
	symbolNodesByResolver map[string]string
	nodeResolvers         map[string]string
	symbolOrigins         map[string][]goSemanticSymbolOrigin
	complete              bool
	beforeSites           map[string]bool
}

type goSemanticPackage struct {
	extractor        *goSemanticExtractor
	typed            goTypedPackage
	files            []goTypedFile
	universeFiles    []goTypedFile
	packageLocator   string
	packageNodeID    string
	parents          map[ast.Node]ast.Node
	owners           map[ast.Node]string
	objectNodes      map[types.Object]string
	objectResolvers  map[types.Object]string
	instanceNodes    map[*ast.Ident]string
	callInitializers map[*ast.ValueSpec]string
	typeSpecNodes    map[*ast.TypeSpec]string
	namedTypes       []goSemanticNamedType
	namedTypeIDs     map[string]bool
	extends          []goSemanticExtends
}

type goSemanticNamedType struct {
	nodeID        string
	named         *types.Named
	interfaceType *types.Interface
	evidence      []Evidence
	condition     Condition
	generated     bool
}

type goSemanticExtends struct {
	sourceID       string
	targetResolver string
	evidence       []Evidence
	condition      Condition
	generated      bool
}

func (s *scannerState) extractGoSemanticGraph(sources []*sourceFile) {
	extractor := &goSemanticExtractor{
		state:                 s,
		sources:               make(map[string]*sourceFile, len(sources)),
		typeNodesByResolver:   map[string]string{},
		symbolNodesByResolver: map[string]string{},
		nodeResolvers:         map[string]string{},
		symbolOrigins:         map[string][]goSemanticSymbolOrigin{},
		complete:              true,
		beforeSites:           make(map[string]bool, len(s.sites)),
	}
	for _, source := range sources {
		extractor.sources[source.RelPath] = source
	}
	for siteID := range s.sites {
		extractor.beforeSites[siteID] = true
	}

	for _, typed := range s.goPackages.TypedPackages {
		context := extractor.newPackage(typed)
		if len(context.files) > 0 {
			extractor.contexts = append(extractor.contexts, context)
		}
	}

	// All package-level types must exist before methods are declared. Go permits
	// a receiver type to be declared after the method's source file.
	for _, context := range extractor.contexts {
		context.declarePackageTypes()
	}
	for _, context := range extractor.contexts {
		context.declareObjects()
		context.recordUniverseNamedTypes()
	}
	for _, context := range extractor.contexts {
		context.recordImportedInterfaces()
	}
	for _, context := range extractor.contexts {
		context.emitExtends()
		context.emitSelections()
		context.emitTypeUsesAndInstances()
	}
	for _, context := range extractor.contexts {
		context.emitCalls()
	}
	extractor.emitImplements()

	extractor.accountSemanticSites()
	if s.goPackages.Status == "loaded" && extractor.complete {
		s.semanticIncomplete = false
	}
}

func (e *goSemanticExtractor) newPackage(typed goTypedPackage) *goSemanticPackage {
	context := &goSemanticPackage{
		extractor:        e,
		typed:            typed,
		packageLocator:   goSemanticPackageLocator(typed),
		parents:          map[ast.Node]ast.Node{},
		owners:           map[ast.Node]string{},
		objectNodes:      map[types.Object]string{},
		objectResolvers:  map[types.Object]string{},
		instanceNodes:    map[*ast.Ident]string{},
		callInitializers: map[*ast.ValueSpec]string{},
		typeSpecNodes:    map[*ast.TypeSpec]string{},
		namedTypeIDs:     map[string]bool{},
	}
	context.packageNodeID = e.packageNodeID(typed)
	for _, file := range typed.Files {
		context.universeFiles = append(context.universeFiles, file)
		// The internal-test universe repeats every normal file with fresh object
		// pointers. The base universe owns normal declarations; the test universe
		// contributes only its _test.go files.
		if typed.ForTest != "" && typed.PkgPath == typed.ForTest && !strings.HasSuffix(file.Path, "_test.go") {
			continue
		}
		context.files = append(context.files, file)
		parents := goSemanticParentMap(file.Syntax)
		for node, parent := range parents {
			context.parents[node] = parent
		}
	}
	return context
}

// recordUniverseNamedTypes retains the augmented internal-test method set
// without re-emitting declarations from normal files. This lets a normal type
// implement an interface declared only in an internal _test.go file while the
// canonical node/site IDs still coalesce repeated normal-package syntax.
func (p *goSemanticPackage) recordUniverseNamedTypes() {
	for _, file := range p.universeFiles {
		ast.Inspect(file.Syntax, func(node ast.Node) bool {
			spec, ok := node.(*ast.TypeSpec)
			if !ok || spec.Name == nil {
				return true
			}
			object, ok := p.typed.TypesInfo.Defs[spec.Name].(*types.TypeName)
			if !ok || object.Parent() != p.typed.Types.Scope() || object.Pkg() == nil {
				return true
			}
			resolver := object.Pkg().Path() + "." + object.Name()
			nodeID := p.extractor.typeNodesByResolver[resolver]
			if nodeID == "" {
				return true
			}
			p.objectNodes[object] = nodeID
			p.objectResolvers[object] = resolver
			p.recordNamedType(nodeID, object, spec.Name, file)
			return true
		})
	}
}

// recordImportedInterfaces adds workspace interfaces using the exact type
// objects imported into this package's universe. Separate module loads may
// otherwise hold equivalent package objects at different addresses, causing a
// cross-module types.Implements comparison to miss a valid relation.
func (p *goSemanticPackage) recordImportedInterfaces() {
	imports := append([]*types.Package(nil), p.typed.Types.Imports()...)
	sort.Slice(imports, func(left, right int) bool { return imports[left].Path() < imports[right].Path() })
	for _, imported := range imports {
		if imported == nil || imported.Scope() == nil {
			continue
		}
		names := imported.Scope().Names()
		sort.Strings(names)
		for _, name := range names {
			object, ok := imported.Scope().Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			resolver := imported.Path() + "." + object.Name()
			nodeID := p.extractor.typeNodesByResolver[resolver]
			if nodeID == "" || p.namedTypeIDs[nodeID] {
				continue
			}
			named := goSemanticNamedFromType(object.Type())
			if named == nil {
				continue
			}
			interfaceType, ok := named.Underlying().(*types.Interface)
			if !ok {
				continue
			}
			reference, ok := p.extractor.namedTypeRecord(nodeID)
			if !ok {
				continue
			}
			p.namedTypeIDs[nodeID] = true
			p.namedTypes = append(p.namedTypes, goSemanticNamedType{
				nodeID: nodeID, named: named, interfaceType: interfaceType.Complete(),
				evidence:  append([]Evidence(nil), reference.evidence...),
				condition: reference.condition, generated: reference.generated,
			})
		}
	}
}

func (e *goSemanticExtractor) namedTypeRecord(nodeID string) (goSemanticNamedType, bool) {
	for _, context := range e.contexts {
		for _, record := range context.namedTypes {
			if record.nodeID == nodeID {
				return record, true
			}
		}
	}
	return goSemanticNamedType{}, false
}

func (e *goSemanticExtractor) packageNodeID(pkg goTypedPackage) string {
	wants := map[string]bool{"go-package:" + pkg.PkgPath: true}
	if pkg.ForTest != "" {
		wants["go-package:"+pkg.ForTest] = true
	}
	var matches []string
	for id, node := range e.state.nodes {
		if node.Kind == "module" && wants[node.Locator] {
			matches = append(matches, id)
		}
	}
	if len(matches) == 0 {
		return e.state.workspaceNodeID
	}
	sort.Strings(matches)
	return matches[0]
}

func goSemanticPackageLocator(pkg goTypedPackage) string {
	return "go:" + pkg.ModulePath + "@workspace#" + pkg.PkgPath
}

func goSemanticParentMap(root ast.Node) map[ast.Node]ast.Node {
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	return parents
}

func (p *goSemanticPackage) declarePackageTypes() {
	for _, file := range p.files {
		ast.Inspect(file.Syntax, func(node ast.Node) bool {
			spec, ok := node.(*ast.TypeSpec)
			if !ok || spec.Name == nil {
				return true
			}
			object, ok := p.typed.TypesInfo.Defs[spec.Name].(*types.TypeName)
			if !ok || object.Parent() != p.typed.Types.Scope() {
				return true
			}
			nodeID := p.ensureType(object, spec.Name, file, p.packageNodeID, "")
			if nodeID == "" {
				return true
			}
			p.owners[spec] = nodeID
			p.typeSpecNodes[spec] = nodeID
			p.recordNamedType(nodeID, object, spec.Name, file)
			return true
		})
	}
}

func (p *goSemanticPackage) declareObjects() {
	// Functions first establish owners for parameters, local definitions, and
	// local type declarations.
	for _, file := range p.files {
		ast.Inspect(file.Syntax, func(node ast.Node) bool {
			declaration, ok := node.(*ast.FuncDecl)
			if !ok || declaration.Name == nil {
				return true
			}
			object, ok := p.typed.TypesInfo.Defs[declaration.Name].(*types.Func)
			if !ok {
				return true
			}
			ownerID, resolver := p.methodOwner(object)
			declaredBy := p.packageNodeID
			if ownerID != "" {
				declaredBy = ownerID
			}
			nodeID := p.ensureSymbol(object, declaration.Name, file, declaredBy, resolver, "")
			if nodeID != "" {
				p.owners[declaration] = nodeID
			}
			return true
		})
	}

	// A local named type needs its enclosing function node, now available.
	for _, file := range p.files {
		ast.Inspect(file.Syntax, func(node ast.Node) bool {
			spec, ok := node.(*ast.TypeSpec)
			if !ok || spec.Name == nil || p.typeSpecNodes[spec] != "" {
				return true
			}
			object, ok := p.typed.TypesInfo.Defs[spec.Name].(*types.TypeName)
			if !ok {
				return true
			}
			ownerID := p.nearestOwner(spec)
			nodeID := p.ensureType(object, spec.Name, file, ownerID, "")
			if nodeID != "" {
				p.owners[spec] = nodeID
				p.typeSpecNodes[spec] = nodeID
			}
			return true
		})
	}

	for _, file := range p.files {
		p.declareTypeMembers(file)
	}
	for _, file := range p.files {
		p.declareValueSpecs(file)
		p.declareClosures(file)
		p.declareRemainingDefinitions(file)
	}
}

func (p *goSemanticPackage) declareTypeMembers(file goTypedFile) {
	ast.Inspect(file.Syntax, func(node ast.Node) bool {
		field, ok := node.(*ast.Field)
		if !ok {
			return true
		}
		fieldList, ok := p.parents[field].(*ast.FieldList)
		if !ok {
			return true
		}
		container := p.parents[fieldList]
		if _, ok := container.(*ast.StructType); !ok {
			if _, ok := container.(*ast.InterfaceType); !ok {
				return true
			}
		}
		typeSpec, ok := p.parents[container].(*ast.TypeSpec)
		if !ok {
			// Members of a nested anonymous struct/interface do not belong to the
			// surrounding named type.
			return true
		}
		ownerID := p.typeSpecNodes[typeSpec]
		if ownerID == "" {
			return true
		}
		ownerResolver := p.extractor.nodeResolvers[ownerID]
		if len(field.Names) == 0 {
			if _, isInterface := container.(*ast.InterfaceType); isInterface {
				p.owners[field] = ownerID
				p.recordExtends(ownerID, field.Type, file)
				return true
			}
			identifier, object := p.embeddedFieldDefinition(field)
			if identifier == nil || object == nil {
				p.owners[field] = ownerID
				return true
			}
			resolver := ownerResolver + "." + object.Name()
			nodeID := p.ensureSymbol(object, identifier, file, ownerID, resolver, "field")
			if nodeID != "" {
				p.owners[field] = nodeID
			}
			return true
		}
		for _, name := range field.Names {
			object := p.typed.TypesInfo.Defs[name]
			if object == nil || name.Name == "_" {
				continue
			}
			resolver := ownerResolver + "." + name.Name
			kind := "field"
			if _, ok := object.(*types.Func); ok {
				resolver = goSemanticMethodResolver(ownerResolver, name.Name, false)
				kind = "method"
			}
			nodeID := p.ensureSymbol(object, name, file, ownerID, resolver, kind)
			if nodeID != "" && p.owners[field] == "" {
				p.owners[field] = nodeID
			}
		}
		return true
	})
}

func (p *goSemanticPackage) embeddedFieldDefinition(field *ast.Field) (*ast.Ident, *types.Var) {
	var identifier *ast.Ident
	var object *types.Var
	ast.Inspect(field.Type, func(node ast.Node) bool {
		if identifier != nil {
			return false
		}
		candidate, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		variable, ok := p.typed.TypesInfo.Defs[candidate].(*types.Var)
		if !ok || !variable.IsField() {
			return true
		}
		identifier = candidate
		object = variable
		return false
	})
	return identifier, object
}

func (p *goSemanticPackage) declareValueSpecs(file goTypedFile) {
	ast.Inspect(file.Syntax, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok {
			return true
		}
		ownerID := p.nearestOwner(spec)
		for _, name := range spec.Names {
			object := p.typed.TypesInfo.Defs[name]
			if object == nil || name.Name == "_" {
				continue
			}
			declaredBy := ownerID
			if object.Parent() == p.typed.Types.Scope() {
				declaredBy = p.packageNodeID
			}
			nodeID := p.ensureSymbol(object, name, file, declaredBy, "", "")
			if nodeID != "" && p.owners[spec] == "" {
				p.owners[spec] = nodeID
			}
		}
		if p.owners[spec] == "" && ownerID == "" {
			p.owners[spec] = p.ensurePackageInitializer(file, spec, "package initialization")
		}
		return true
	})
}

func (p *goSemanticPackage) declareClosures(file goTypedFile) {
	ast.Inspect(file.Syntax, func(node ast.Node) bool {
		literal, ok := node.(*ast.FuncLit)
		if !ok {
			return true
		}
		ownerID := p.nearestOwner(literal)
		if ownerID == "" {
			return true
		}
		evidence := p.evidence(file, literal, "closure", nil)
		identity := map[string]any{
			"language": "go", "package_locator": p.packageLocator,
			"symbol_kind": "closure", "identity_kind": "anonymous",
			"enclosing_symbol": ownerID, "relative_path": file.Path,
			"span": goSemanticSpan(evidence[0]),
		}
		nodeID := stableIDFromValue("symbol", identity)
		nodeValue := Node{
			ID: nodeID, Kind: "symbol", Locator: "go-symbol:" + nodeID,
			DisplayName: "closure",
			Properties: map[string]any{
				"language": "go", "package_locator": p.packageLocator,
				"symbol_kind": "closure", "canonical_identity": identity,
			},
		}
		if !p.extractor.addNode(nodeValue, file.Path) {
			return true
		}
		p.owners[literal] = nodeID
		p.extractor.nodeResolvers[nodeID] = nodeID
		p.extractor.addRelation("declares", ownerID, nodeID, p.condition(file.Path), evidence, p.generated(file.Path))
		return true
	})
}

func (p *goSemanticPackage) ensurePackageInitializer(file goTypedFile, node ast.Node, displayName string) string {
	evidence := p.evidence(file, node, displayName, nil)
	identity := map[string]any{
		"language": "go", "package_locator": p.packageLocator,
		"symbol_kind": "package_initializer", "identity_kind": "anonymous",
		"generated_from": p.packageNodeID, "relative_path": file.Path,
		"span": goSemanticSpan(evidence[0]),
	}
	nodeID := stableIDFromValue("symbol", identity)
	nodeValue := Node{
		ID: nodeID, Kind: "symbol", Locator: "go-symbol:" + nodeID,
		DisplayName: displayName,
		Properties: map[string]any{
			"language": "go", "package_locator": p.packageLocator,
			"symbol_kind": "package_initializer", "canonical_identity": identity,
		},
	}
	if !p.extractor.addNode(nodeValue, file.Path) {
		return ""
	}
	p.extractor.nodeResolvers[nodeID] = nodeID
	p.extractor.addRelation("declares", p.packageNodeID, nodeID, p.condition(file.Path), evidence, p.generated(file.Path))
	return nodeID
}

func (p *goSemanticPackage) declareRemainingDefinitions(file goTypedFile) {
	ast.Inspect(file.Syntax, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok || identifier.Name == "_" {
			return true
		}
		object := p.typed.TypesInfo.Defs[identifier]
		if object == nil {
			return true
		}
		if _, ok := object.(*types.PkgName); ok {
			return true
		}
		if p.objectNodes[object] != "" {
			return true
		}
		ownerID := p.nearestOwner(identifier)
		declaredBy := ownerID
		if object.Parent() == p.typed.Types.Scope() {
			declaredBy = p.packageNodeID
		}
		switch typed := object.(type) {
		case *types.TypeName:
			p.ensureType(typed, identifier, file, declaredBy, "")
		default:
			p.ensureSymbol(object, identifier, file, declaredBy, "", "")
		}
		return true
	})
}

func (p *goSemanticPackage) ensureType(object *types.TypeName, identifier *ast.Ident, file goTypedFile, declaredBy, explicitResolver string) string {
	if nodeID := p.objectNodes[object]; nodeID != "" {
		return nodeID
	}
	resolver := explicitResolver
	if resolver == "" && object.Parent() == p.typed.Types.Scope() && object.Pkg() != nil {
		resolver = object.Pkg().Path() + "." + object.Name()
	}
	evidence := p.evidence(file, identifier, object.Name(), nil)
	if resolver == "" {
		if declaredBy == "" {
			p.extractor.fail("go_semantic_owner", file.Path, "local type "+object.Name()+" has no semantic owner")
			return ""
		}
		ownerResolver := p.extractor.nodeResolvers[declaredBy]
		if ownerResolver == "" {
			ownerResolver = declaredBy
		}
		primary := evidence[0]
		resolver = fmt.Sprintf("%s.%s@%s:%d:%d", ownerResolver, object.Name(), file.Path, primary.StartLine, primary.StartColumn)
	}
	typeKind := goSemanticTypeKind(object)
	identity := map[string]any{
		"language": "go", "package_locator": p.packageLocator,
		"type_kind": typeKind, "resolver_identity": resolver,
	}
	nodeID := stableIDFromValue("type", identity)
	nodeValue := Node{
		ID: nodeID, Kind: "type", Locator: "go-type:" + resolver,
		DisplayName: object.Name(),
		Properties: map[string]any{
			"language": "go", "package_locator": p.packageLocator,
			"type_kind": typeKind, "canonical_identity": identity,
		},
	}
	if !p.extractor.addNode(nodeValue, file.Path) {
		return ""
	}
	p.objectNodes[object] = nodeID
	p.objectResolvers[object] = resolver
	p.extractor.nodeResolvers[nodeID] = resolver
	if object.Parent() == p.typed.Types.Scope() {
		p.extractor.registerResolver(p.extractor.typeNodesByResolver, resolver, nodeID, file.Path)
	}
	if declaredBy != "" {
		p.extractor.addRelation("declares", declaredBy, nodeID, p.condition(file.Path), evidence, p.generated(file.Path))
	}
	return nodeID
}

func (p *goSemanticPackage) ensureSymbol(object types.Object, identifier *ast.Ident, file goTypedFile, declaredBy, explicitResolver, explicitKind string) string {
	if nodeID := p.objectNodes[object]; nodeID != "" {
		return nodeID
	}
	symbolKind := explicitKind
	if symbolKind == "" {
		symbolKind = p.symbolKind(object, identifier)
	}
	if symbolKind == "" {
		return ""
	}
	if symbolKind == "package_initializer" {
		nodeID := p.ensurePackageInitializer(file, identifier, object.Name())
		if nodeID != "" {
			p.objectNodes[object] = nodeID
			p.objectResolvers[object] = nodeID
		}
		return nodeID
	}
	resolver := explicitResolver
	named := resolver != "" || object.Parent() == p.typed.Types.Scope()
	if function, ok := object.(*types.Func); ok {
		if signature, ok := function.Type().(*types.Signature); ok && signature.Recv() != nil {
			if receiver, _ := goSemanticReceiverNamed(signature.Recv().Type()); receiver != nil && receiver.Obj() != nil {
				named = true
				if resolver == "" {
					resolver = goSemanticFunctionResolver(function)
				}
			}
		}
	}
	if variable, ok := object.(*types.Var); ok && variable.IsField() && explicitResolver != "" {
		named = true
	}
	if named && resolver == "" && object.Pkg() != nil {
		resolver = object.Pkg().Path() + "." + object.Name()
	}
	evidence := p.evidence(file, identifier, object.Name(), nil)
	identity := map[string]any{
		"language": "go", "package_locator": p.packageLocator,
		"symbol_kind": symbolKind,
	}
	locator := ""
	if named {
		if resolver == "" {
			p.extractor.fail("go_semantic_identity", file.Path, "named symbol "+object.Name()+" has no resolver identity")
			return ""
		}
		identity["identity_kind"] = "named"
		identity["resolver_identity"] = resolver
		locator = "go-symbol:" + resolver
	} else {
		if declaredBy == "" || p.extractor.state.nodes[declaredBy].Kind != "symbol" {
			p.extractor.fail("go_semantic_owner", file.Path, "local symbol "+object.Name()+" has no enclosing symbol")
			return ""
		}
		identity["identity_kind"] = "local"
		identity["enclosing_symbol"] = declaredBy
		identity["relative_path"] = file.Path
		identity["span"] = goSemanticSpan(evidence[0])
		locator = "go-symbol:" + declaredBy + "@" + file.Path + fmt.Sprintf(":%d:%d", evidence[0].StartLine, evidence[0].StartColumn)
	}
	nodeID := stableIDFromValue("symbol", identity)
	nodeValue := Node{
		ID: nodeID, Kind: "symbol", Locator: locator, DisplayName: object.Name(),
		Properties: map[string]any{
			"language": "go", "package_locator": p.packageLocator,
			"symbol_kind": symbolKind, "canonical_identity": identity,
		},
	}
	if !p.extractor.addNode(nodeValue, file.Path) {
		return ""
	}
	p.objectNodes[object] = nodeID
	p.objectResolvers[object] = resolver
	if resolver == "" {
		resolver = nodeID
	}
	p.extractor.nodeResolvers[nodeID] = resolver
	if named {
		p.extractor.registerResolver(p.extractor.symbolNodesByResolver, resolver, nodeID, file.Path)
		p.extractor.registerSymbolOrigin(nodeID, p.typed)
	}
	if declaredBy != "" {
		p.extractor.addRelation("declares", declaredBy, nodeID, p.condition(file.Path), evidence, p.generated(file.Path))
	}
	return nodeID
}

func (p *goSemanticPackage) symbolKind(object types.Object, identifier *ast.Ident) string {
	switch typed := object.(type) {
	case *types.Func:
		if typed.Name() == "init" {
			return "package_initializer"
		}
		if signature, ok := typed.Type().(*types.Signature); ok && signature.Recv() != nil {
			return "method"
		}
		return "function"
	case *types.Var:
		if typed.IsField() {
			return "field"
		}
		if typed.Parent() == p.typed.Types.Scope() {
			return "variable"
		}
		if p.identifierIsParameter(identifier) {
			return "parameter"
		}
		return "local_variable"
	case *types.Const:
		if typed.Parent() == p.typed.Types.Scope() {
			return "constant"
		}
		return "local_constant"
	case *types.Label:
		return "local_label"
	default:
		return ""
	}
}

func (p *goSemanticPackage) identifierIsParameter(identifier *ast.Ident) bool {
	for current := ast.Node(identifier); current != nil; current = p.parents[current] {
		switch node := current.(type) {
		case *ast.Field:
			for _, name := range node.Names {
				if name == identifier {
					if variable, ok := p.typed.TypesInfo.Defs[identifier].(*types.Var); ok && variable.IsField() {
						return false
					}
					return p.fieldBelongsToFunction(node)
				}
			}
		case *ast.FuncDecl, *ast.FuncLit:
			return false
		}
	}
	return false
}

func (p *goSemanticPackage) fieldBelongsToFunction(field *ast.Field) bool {
	for current := p.parents[field]; current != nil; current = p.parents[current] {
		switch current.(type) {
		case *ast.FuncType:
			return true
		case *ast.StructType, *ast.InterfaceType:
			return false
		case *ast.FuncDecl, *ast.FuncLit:
			return true
		}
	}
	return false
}

func goSemanticTypeKind(object *types.TypeName) string {
	if object.IsAlias() {
		return "type_alias"
	}
	switch typed := object.Type().(type) {
	case *types.TypeParam:
		return "type_parameter"
	case *types.Named:
		switch typed.Underlying().(type) {
		case *types.Struct:
			return "struct"
		case *types.Interface:
			return "interface"
		default:
			return "named_type"
		}
	default:
		return "named_type"
	}
}

func (p *goSemanticPackage) methodOwner(function *types.Func) (string, string) {
	signature, ok := function.Type().(*types.Signature)
	if !ok || signature.Recv() == nil {
		return "", ""
	}
	named, pointer := goSemanticReceiverNamed(signature.Recv().Type())
	if named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
		return "", goSemanticFunctionResolver(function)
	}
	receiverResolver := named.Obj().Pkg().Path() + "." + named.Obj().Name()
	ownerID := p.objectNodes[named.Obj()]
	if ownerID == "" {
		ownerID = p.extractor.typeNodesByResolver[receiverResolver]
	}
	return ownerID, goSemanticMethodResolver(receiverResolver, function.Name(), pointer)
}

func goSemanticReceiverNamed(receiver types.Type) (*types.Named, bool) {
	pointer := false
	if typed, ok := receiver.(*types.Pointer); ok {
		pointer = true
		receiver = typed.Elem()
	}
	named, _ := receiver.(*types.Named)
	return named, pointer
}

func goSemanticFunctionResolver(function *types.Func) string {
	if function == nil || function.Pkg() == nil {
		return ""
	}
	signature, _ := function.Type().(*types.Signature)
	if signature == nil || signature.Recv() == nil {
		return function.Pkg().Path() + "." + function.Name()
	}
	named, pointer := goSemanticReceiverNamed(signature.Recv().Type())
	if named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
		return function.Pkg().Path() + "." + function.Name()
	}
	receiverResolver := named.Obj().Pkg().Path() + "." + named.Obj().Name()
	return goSemanticMethodResolver(receiverResolver, function.Name(), pointer)
}

func goSemanticMethodResolver(receiverResolver, methodName string, pointer bool) string {
	packagePath := receiverResolver
	typeName := receiverResolver
	if dot := strings.LastIndex(receiverResolver, "."); dot >= 0 {
		packagePath = receiverResolver[:dot]
		typeName = receiverResolver[dot+1:]
	}
	if pointer {
		typeName = "*" + typeName
	}
	return packagePath + ".(" + typeName + ")." + methodName
}

func (p *goSemanticPackage) recordNamedType(nodeID string, object *types.TypeName, identifier *ast.Ident, file goTypedFile) {
	if p.namedTypeIDs[nodeID] {
		return
	}
	named := goSemanticNamedFromType(object.Type())
	if named == nil {
		return
	}
	record := goSemanticNamedType{
		nodeID: nodeID, named: named,
		evidence:  p.evidence(file, identifier, object.Name(), nil),
		condition: p.condition(file.Path), generated: p.generated(file.Path),
	}
	if interfaceType, ok := named.Underlying().(*types.Interface); ok {
		record.interfaceType = interfaceType.Complete()
	}
	p.namedTypeIDs[nodeID] = true
	p.namedTypes = append(p.namedTypes, record)
}

func (p *goSemanticPackage) recordExtends(sourceID string, expression ast.Expr, file goTypedFile) {
	named := goSemanticNamedFromType(p.typed.TypesInfo.TypeOf(expression))
	if named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
		return
	}
	if _, ok := named.Underlying().(*types.Interface); !ok {
		return
	}
	p.extends = append(p.extends, goSemanticExtends{
		sourceID:       sourceID,
		targetResolver: named.Obj().Pkg().Path() + "." + named.Obj().Name(),
		evidence:       p.evidence(file, expression, "embedded interface", nil),
		condition:      p.condition(file.Path), generated: p.generated(file.Path),
	})
}

func goSemanticNamedFromType(value types.Type) *types.Named {
	switch typed := value.(type) {
	case *types.Named:
		return typed
	case *types.Alias:
		return goSemanticNamedFromType(types.Unalias(typed))
	case *types.Pointer:
		return goSemanticNamedFromType(typed.Elem())
	default:
		return nil
	}
}

func (p *goSemanticPackage) emitExtends() {
	for _, relation := range p.extends {
		targetID := p.extractor.typeNodesByResolver[relation.targetResolver]
		if targetID == "" {
			targetID = p.extractor.ensureExternalType(relation.targetResolver, goSemanticResolverName(relation.targetResolver))
		}
		p.extractor.addRelation("extends", relation.sourceID, targetID, relation.condition, relation.evidence, relation.generated)
	}
}

func (e *goSemanticExtractor) emitImplements() {
	var namedTypes []goSemanticNamedType
	for _, context := range e.contexts {
		namedTypes = append(namedTypes, context.namedTypes...)
	}
	for _, concrete := range namedTypes {
		for _, contract := range namedTypes {
			if contract.interfaceType == nil || concrete.nodeID == contract.nodeID {
				continue
			}
			// go/types deliberately leaves Implements behavior unspecified for
			// uninstantiated generic named types. Emitting an exact relation for
			// their origins would also make the result depend on type-parameter
			// spelling. Concrete instances are recorded separately and are safe
			// to compare after substitution.
			if goSemanticUninstantiatedGeneric(concrete.named) || goSemanticUninstantiatedGeneric(contract.named) {
				continue
			}
			if !goSemanticVariantsCompatible(concrete.condition, contract.condition) {
				continue
			}
			implemented := goSemanticTypeImplements(concrete.named, contract.interfaceType)
			pointerOnly := false
			if !implemented && concrete.interfaceType == nil {
				implemented = goSemanticTypeImplements(types.NewPointer(concrete.named), contract.interfaceType)
				pointerOnly = implemented
			}
			if !implemented {
				continue
			}
			evidence := append([]Evidence(nil), concrete.evidence...)
			if len(evidence) > 0 {
				evidence[0].Properties = map[string]any{"algorithm": "go-method-set", "pointer_receiver": pointerOnly}
			}
			condition := combineConditions(concrete.condition, contract.condition)
			e.addRelation("implements", concrete.nodeID, contract.nodeID, condition, evidence, concrete.generated || contract.generated)
		}
	}
}

func goSemanticUninstantiatedGeneric(named *types.Named) bool {
	if named == nil || named.TypeParams() == nil || named.TypeParams().Len() == 0 {
		return false
	}
	return named.TypeArgs() == nil || named.TypeArgs().Len() == 0
}

func goSemanticTypeImplements(concrete types.Type, contract *types.Interface) bool {
	if types.Implements(concrete, contract) {
		return true
	}
	contract = contract.Complete()
	if !contract.IsMethodSet() {
		return false
	}
	available := map[string]bool{}
	methodSet := types.NewMethodSet(concrete)
	for index := 0; index < methodSet.Len(); index++ {
		method, ok := methodSet.At(index).Obj().(*types.Func)
		if !ok {
			continue
		}
		// The path/name resolver used by this cross-universe fallback cannot
		// prove that type parameters from two lexical scopes correspond. Keep
		// those comparisons on the native go/types path above, where object
		// identity is available, instead of risking a false exact edge.
		if goSemanticContainsTypeParameter(method.Type(), map[types.Type]bool{}) {
			continue
		}
		available[goSemanticMemberIdentity(method)+":"+goSemanticTypeShape(method.Type())] = true
	}
	for index := 0; index < contract.NumMethods(); index++ {
		method := contract.Method(index)
		if goSemanticContainsTypeParameter(method.Type(), map[types.Type]bool{}) {
			return false
		}
		key := goSemanticMemberIdentity(method) + ":" + goSemanticTypeShape(method.Type())
		if !available[key] {
			return false
		}
	}
	return true
}

func goSemanticContainsTypeParameter(value types.Type, seen map[types.Type]bool) bool {
	if value == nil {
		return false
	}
	if _, ok := value.(*types.TypeParam); ok {
		return true
	}
	if seen[value] {
		return false
	}
	seen[value] = true

	switch typed := value.(type) {
	case *types.Pointer:
		return goSemanticContainsTypeParameter(typed.Elem(), seen)
	case *types.Slice:
		return goSemanticContainsTypeParameter(typed.Elem(), seen)
	case *types.Array:
		return goSemanticContainsTypeParameter(typed.Elem(), seen)
	case *types.Map:
		return goSemanticContainsTypeParameter(typed.Key(), seen) || goSemanticContainsTypeParameter(typed.Elem(), seen)
	case *types.Chan:
		return goSemanticContainsTypeParameter(typed.Elem(), seen)
	case *types.Tuple:
		for index := 0; index < typed.Len(); index++ {
			if goSemanticContainsTypeParameter(typed.At(index).Type(), seen) {
				return true
			}
		}
	case *types.Signature:
		// Receiver type parameters describe the concrete container, not the
		// method signature that must match an interface method.
		return goSemanticContainsTypeParameter(typed.Params(), seen) || goSemanticContainsTypeParameter(typed.Results(), seen)
	case *types.Named:
		if typed.TypeArgs() != nil {
			for index := 0; index < typed.TypeArgs().Len(); index++ {
				if goSemanticContainsTypeParameter(typed.TypeArgs().At(index), seen) {
					return true
				}
			}
		}
	case *types.Alias:
		return goSemanticContainsTypeParameter(types.Unalias(typed), seen)
	case *types.Struct:
		for index := 0; index < typed.NumFields(); index++ {
			if goSemanticContainsTypeParameter(typed.Field(index).Type(), seen) {
				return true
			}
		}
	case *types.Interface:
		complete := typed.Complete()
		for index := 0; index < complete.NumMethods(); index++ {
			if goSemanticContainsTypeParameter(complete.Method(index).Type(), seen) {
				return true
			}
		}
		for index := 0; index < complete.NumEmbeddeds(); index++ {
			if goSemanticContainsTypeParameter(complete.EmbeddedType(index), seen) {
				return true
			}
		}
	case *types.Union:
		for index := 0; index < typed.Len(); index++ {
			if goSemanticContainsTypeParameter(typed.Term(index).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func goSemanticVariantsCompatible(left, right Condition) bool {
	leftVariant := goSemanticConditionValue(left, "go.package_variant")
	rightVariant := goSemanticConditionValue(right, "go.package_variant")
	return leftVariant == "" || rightVariant == "" || leftVariant == rightVariant
}

func goSemanticConditionValue(condition Condition, key string) string {
	if condition.Op == "eq" && condition.Key == key {
		return condition.Value
	}
	value := ""
	for _, child := range condition.Conditions {
		childValue := goSemanticConditionValue(child, key)
		if childValue == "" {
			continue
		}
		if value != "" && value != childValue {
			return "<conflict>"
		}
		value = childValue
	}
	if condition.Condition != nil {
		childValue := goSemanticConditionValue(*condition.Condition, key)
		if value != "" && childValue != "" && value != childValue {
			return "<conflict>"
		}
		if value == "" {
			value = childValue
		}
	}
	return value
}

func (p *goSemanticPackage) emitSelections() {
	for _, file := range p.files {
		ast.Inspect(file.Syntax, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			selection := p.typed.TypesInfo.Selections[selector]
			if selection == nil || selection.Obj() == nil {
				return true
			}
			object := selection.Obj()
			if p.objectNodes[object] != "" {
				return true
			}
			if function, ok := object.(*types.Func); ok {
				resolver := goSemanticFunctionResolver(function)
				packagePath := goSemanticFunctionPackagePath(function)
				if nodeID := p.visibleSymbolNode(resolver, packagePath); nodeID != "" {
					p.objectNodes[object] = nodeID
					p.objectResolvers[object] = resolver
				}
			}
			return true
		})
	}
}

func (p *goSemanticPackage) emitTypeUsesAndInstances() {
	for _, file := range p.files {
		ast.Inspect(file.Syntax, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			if instance, ok := p.typed.TypesInfo.Instances[identifier]; ok {
				p.emitInstance(file, identifier, instance)
			}
			object, ok := p.typed.TypesInfo.Uses[identifier].(*types.TypeName)
			if !ok {
				return true
			}
			ownerID := p.nearestOwner(identifier)
			if ownerID == "" {
				p.extractor.fail("go_semantic_owner", file.Path, fmt.Sprintf("type use %q has no semantic owner", identifier.Name))
				return true
			}
			targetID, status, precision, resolver := p.typeUseTarget(object)
			if targetID == "" {
				return true
			}
			evidence := p.evidence(file, identifier, identifier.Name, map[string]any{"resolver_identity": resolver})
			p.extractor.addTypeUse(ownerID, targetID, identifier.Name, status, precision, p.condition(file.Path), evidence, p.generated(file.Path))
			return true
		})
	}
}

func (p *goSemanticPackage) typeUseTarget(object *types.TypeName) (string, string, string, string) {
	if targetID := p.objectNodes[object]; targetID != "" {
		return targetID, "resolved", "exact", p.objectResolvers[object]
	}
	resolver := goSemanticTypeResolver(object)
	if targetID := p.extractor.typeNodesByResolver[resolver]; targetID != "" {
		return targetID, "resolved", "exact", resolver
	}
	targetID := p.extractor.ensureExternalType(resolver, object.Name())
	if targetID == "" {
		return "", "", "", resolver
	}
	return targetID, "external", "exact", resolver
}

func goSemanticTypeResolver(object *types.TypeName) string {
	if object == nil {
		return "unknown"
	}
	if object.Pkg() == nil {
		return "builtin." + object.Name()
	}
	return object.Pkg().Path() + "." + object.Name()
}

func goSemanticResolverName(resolver string) string {
	if index := strings.LastIndex(resolver, "."); index >= 0 && index+1 < len(resolver) {
		return resolver[index+1:]
	}
	return resolver
}

func (e *goSemanticExtractor) ensureExternalType(resolver, displayName string) string {
	identity := map[string]any{"language": "go", "resolver_identity": resolver, "target_kind": "type"}
	targetID := stableIDFromValue("external_system", identity)
	nodeValue := Node{
		ID: targetID, Kind: "external_system", Locator: "go-type:" + resolver,
		DisplayName: displayName,
		Properties:  map[string]any{"language": "go", "external": true, "target_kind": "type", "resolver_identity": resolver},
	}
	if !e.addNode(nodeValue, "") {
		return ""
	}
	return targetID
}

func (p *goSemanticPackage) emitInstance(file goTypedFile, identifier *ast.Ident, instance types.Instance) {
	object := p.typed.TypesInfo.Uses[identifier]
	if object == nil {
		object = p.typed.TypesInfo.Defs[identifier]
	}
	if object == nil {
		return
	}
	var nodeKind, semanticKind, originResolver, originNodeID string
	switch typed := object.(type) {
	case *types.TypeName:
		nodeKind = "type"
		semanticKind = "generic_instance"
		originResolver = goSemanticTypeResolver(typed)
		originNodeID = p.objectNodes[typed]
		if originNodeID == "" {
			originNodeID = p.extractor.typeNodesByResolver[originResolver]
		}
	case *types.Func:
		nodeKind = "symbol"
		semanticKind = "function_instance"
		originResolver = goSemanticFunctionResolver(typed)
		originNodeID = p.objectNodes[typed]
		packagePath := goSemanticFunctionPackagePath(typed)
		if originNodeID != "" && !p.symbolNodeVisible(originNodeID, packagePath) {
			originNodeID = ""
		}
		if originNodeID == "" {
			originNodeID = p.visibleSymbolNode(originResolver, packagePath)
		}
		if originNodeID != "" {
			originResolver = p.extractor.nodeResolvers[originNodeID]
		}
	default:
		return
	}
	typeArguments := make([]string, 0, instance.TypeArgs.Len())
	for index := 0; index < instance.TypeArgs.Len(); index++ {
		typeArguments = append(typeArguments, p.typeArgumentIdentity(instance.TypeArgs.At(index)))
	}
	resolver := originResolver + "[" + strings.Join(typeArguments, ",") + "]"
	ownerID := p.nearestOwner(identifier)
	if ownerID == "" {
		p.extractor.fail("go_semantic_owner", file.Path, fmt.Sprintf("generic instance %q has no semantic owner", resolver))
		return
	}
	evidence := p.evidence(file, identifier, resolver, map[string]any{"generic_origin": originResolver})
	if originNodeID == "" {
		externalIdentity := map[string]any{
			"language": "go", "target_kind": "generic_instance",
			"generic_origin": originResolver, "type_arguments": typeArguments,
			"resolver_identity": resolver,
		}
		externalID := stableIDFromValue("external_system", externalIdentity)
		externalNode := Node{
			ID: externalID, Kind: "external_system", Locator: "go-generic:" + resolver,
			DisplayName: object.Name() + "[" + strings.Join(typeArguments, ", ") + "]",
			Properties: map[string]any{
				"language": "go", "external": true, "target_kind": "generic_instance",
				"generic_origin": originResolver, "type_arguments": typeArguments,
				"resolver_identity": resolver,
			},
		}
		if p.extractor.addNode(externalNode, file.Path) {
			p.instanceNodes[identifier] = externalID
			p.extractor.nodeResolvers[externalID] = resolver
			p.extractor.addRelation("instantiates", ownerID, externalID, p.condition(file.Path), evidence, p.generated(file.Path))
		}
		return
	}
	originNode, ok := p.extractor.state.nodes[originNodeID]
	if !ok {
		p.extractor.fail("go_semantic_identity", file.Path, "generic origin node is missing: "+originNodeID)
		return
	}
	packageLocator, _ := originNode.Properties["package_locator"].(string)
	if packageLocator == "" {
		p.extractor.fail("go_semantic_identity", file.Path, "generic origin lacks package locator: "+originNodeID)
		return
	}
	identity := map[string]any{
		"language": "go", "package_locator": packageLocator,
		"generic_origin": originResolver, "type_arguments": typeArguments,
		"resolver_identity": resolver,
	}
	properties := map[string]any{"language": "go", "package_locator": packageLocator, "canonical_identity": identity}
	if nodeKind == "symbol" {
		identity["symbol_kind"] = semanticKind
		identity["identity_kind"] = "named"
		properties["symbol_kind"] = semanticKind
	} else {
		identity["type_kind"] = semanticKind
		properties["type_kind"] = semanticKind
	}
	nodeID := stableIDFromValue(nodeKind, identity)
	nodeValue := Node{
		ID: nodeID, Kind: nodeKind, Locator: "go-" + nodeKind + ":" + resolver,
		DisplayName: object.Name() + "[" + strings.Join(typeArguments, ", ") + "]",
		Properties:  properties,
	}
	if !p.extractor.addNode(nodeValue, file.Path) {
		return
	}
	p.instanceNodes[identifier] = nodeID
	p.extractor.nodeResolvers[nodeID] = resolver
	if nodeKind == "type" {
		p.recordInstanceNamedType(nodeID, instance.Type, evidence, file.Path)
	}
	p.extractor.addRelation("instantiates", ownerID, nodeID, p.condition(file.Path), evidence, p.generated(file.Path))
}

func (p *goSemanticPackage) recordInstanceNamedType(nodeID string, value types.Type, evidence []Evidence, path string) {
	if p.namedTypeIDs[nodeID] {
		return
	}
	named := goSemanticNamedFromType(value)
	if named == nil {
		return
	}
	record := goSemanticNamedType{
		nodeID: nodeID, named: named, evidence: append([]Evidence(nil), evidence...),
		condition: p.condition(path), generated: p.generated(path),
	}
	if interfaceType, ok := named.Underlying().(*types.Interface); ok {
		record.interfaceType = interfaceType.Complete()
	}
	p.namedTypeIDs[nodeID] = true
	p.namedTypes = append(p.namedTypes, record)
}

func (p *goSemanticPackage) typeArgumentIdentity(value types.Type) string {
	return goSemanticCanonicalType(value, func(object types.Object) string {
		if resolver := p.objectResolvers[object]; resolver != "" {
			return resolver
		}
		return goSemanticObjectResolver(object)
	})
}

func goSemanticTypeShape(value types.Type) string {
	return goSemanticCanonicalType(value, goSemanticObjectResolver)
}

func goSemanticCanonicalType(value types.Type, resolve func(types.Object) string) string {
	if value == nil {
		return "<nil>"
	}
	switch typed := value.(type) {
	case *types.Basic:
		return types.TypeString(typed, goSemanticPackageQualifier)
	case *types.TypeParam:
		return resolve(typed.Obj())
	case *types.Named:
		resolver := resolve(typed.Obj())
		if typed.TypeArgs() == nil || typed.TypeArgs().Len() == 0 {
			return resolver
		}
		arguments := make([]string, 0, typed.TypeArgs().Len())
		for index := 0; index < typed.TypeArgs().Len(); index++ {
			arguments = append(arguments, goSemanticCanonicalType(typed.TypeArgs().At(index), resolve))
		}
		return resolver + "[" + strings.Join(arguments, ",") + "]"
	case *types.Alias:
		return goSemanticCanonicalType(types.Unalias(typed), resolve)
	case *types.Pointer:
		return "*" + goSemanticCanonicalType(typed.Elem(), resolve)
	case *types.Slice:
		return "[]" + goSemanticCanonicalType(typed.Elem(), resolve)
	case *types.Array:
		return "[" + strconv.FormatInt(typed.Len(), 10) + "]" + goSemanticCanonicalType(typed.Elem(), resolve)
	case *types.Map:
		return "map[" + goSemanticCanonicalType(typed.Key(), resolve) + "]" + goSemanticCanonicalType(typed.Elem(), resolve)
	case *types.Chan:
		prefix := "chan "
		if typed.Dir() == types.SendOnly {
			prefix = "chan<- "
		} else if typed.Dir() == types.RecvOnly {
			prefix = "<-chan "
		}
		return prefix + goSemanticCanonicalType(typed.Elem(), resolve)
	case *types.Tuple:
		return goSemanticTupleIdentity(typed, false, resolve)
	case *types.Signature:
		parameters := goSemanticTupleIdentity(typed.Params(), typed.Variadic(), resolve)
		results := goSemanticTupleIdentity(typed.Results(), false, resolve)
		return "func(" + parameters + ")(" + results + ")"
	case *types.Struct:
		fields := make([]string, 0, typed.NumFields())
		for index := 0; index < typed.NumFields(); index++ {
			field := typed.Field(index)
			fields = append(fields, strings.Join([]string{
				goSemanticMemberIdentity(field),
				strconv.FormatBool(field.Embedded()),
				strconv.Quote(typed.Tag(index)),
				goSemanticCanonicalType(field.Type(), resolve),
			}, ":"))
		}
		return "struct{" + strings.Join(fields, ";") + "}"
	case *types.Interface:
		complete := typed.Complete()
		methods := make([]string, 0, complete.NumMethods())
		for index := 0; index < complete.NumMethods(); index++ {
			method := complete.Method(index)
			methods = append(methods, goSemanticMemberIdentity(method)+":"+goSemanticCanonicalType(method.Type(), resolve))
		}
		sort.Strings(methods)
		// Complete already flattens embedded method-only interfaces into the
		// total method set. Retaining their syntactic embedding as well would
		// split identical types such as interface{ M() } and interface{ I }
		// where I's sole method is M.
		if complete.IsMethodSet() {
			return "interface{methods:" + strings.Join(methods, ";") + "}"
		}
		embedded := make([]string, 0, complete.NumEmbeddeds())
		for index := 0; index < complete.NumEmbeddeds(); index++ {
			embedded = append(embedded, goSemanticCanonicalType(complete.EmbeddedType(index), resolve))
		}
		sort.Strings(embedded)
		return "interface{methods:" + strings.Join(methods, ";") + "|embedded:" + strings.Join(embedded, ";") + "}"
	case *types.Union:
		terms := make([]string, 0, typed.Len())
		for index := 0; index < typed.Len(); index++ {
			term := typed.Term(index)
			prefix := ""
			if term.Tilde() {
				prefix = "~"
			}
			terms = append(terms, prefix+goSemanticCanonicalType(term.Type(), resolve))
		}
		sort.Strings(terms)
		return "union{" + strings.Join(terms, "|") + "}"
	default:
		return fmt.Sprintf("unknown-type(%T)", value)
	}
}

func goSemanticTupleIdentity(tuple *types.Tuple, variadic bool, resolve func(types.Object) string) string {
	if tuple == nil {
		return ""
	}
	items := make([]string, 0, tuple.Len())
	for index := 0; index < tuple.Len(); index++ {
		itemType := tuple.At(index).Type()
		if variadic && index == tuple.Len()-1 {
			if slice, ok := itemType.(*types.Slice); ok {
				items = append(items, "..."+goSemanticCanonicalType(slice.Elem(), resolve))
				continue
			}
		}
		items = append(items, goSemanticCanonicalType(itemType, resolve))
	}
	return strings.Join(items, ",")
}

func goSemanticObjectResolver(object types.Object) string {
	if object == nil {
		return "<nil-object>"
	}
	if object.Pkg() == nil {
		return object.Name()
	}
	return object.Pkg().Path() + "." + object.Name()
}

func goSemanticMemberIdentity(object types.Object) string {
	if object == nil || object.Pkg() == nil || object.Exported() {
		if object == nil {
			return "<nil-member>"
		}
		return object.Name()
	}
	return object.Pkg().Path() + "." + object.Name()
}

func goSemanticPackageQualifier(pkg *types.Package) string {
	if pkg == nil {
		return ""
	}
	return pkg.Path()
}

func (p *goSemanticPackage) nearestOwner(node ast.Node) string {
	for current := p.parents[node]; current != nil; current = p.parents[current] {
		if ownerID := p.owners[current]; ownerID != "" {
			return ownerID
		}
	}
	return ""
}

func (p *goSemanticPackage) condition(path string) Condition {
	condition := AlwaysCondition()
	if source := p.extractor.sources[path]; source != nil {
		condition = canonicalCondition(source.Condition)
	}
	if p.typed.ForTest == "" {
		return condition
	}
	variant := "external_test"
	if p.typed.PkgPath == p.typed.ForTest {
		variant = "internal_test"
	}
	return combineConditions(condition, Condition{Op: "eq", Key: "go.package_variant", Value: variant})
}

func (p *goSemanticPackage) generated(path string) bool {
	if source := p.extractor.sources[path]; source != nil {
		return source.Generated
	}
	return false
}

func (p *goSemanticPackage) evidence(file goTypedFile, node ast.Node, detail string, properties map[string]any) []Evidence {
	start := p.typed.FileSet.PositionFor(node.Pos(), false)
	end := p.typed.FileSet.PositionFor(node.End(), false)
	if properties == nil {
		properties = map[string]any{}
	}
	return []Evidence{{
		Kind: "semantic", Extractor: "go-types", ExtractorVersion: AdapterVersion,
		Path: cleanSlash(file.Path), StartLine: start.Line, StartColumn: start.Column,
		EndLine: end.Line, EndColumn: end.Column, Detail: detail, Properties: properties,
	}}
}

func (e *goSemanticExtractor) addNode(node Node, path string) bool {
	if err := addNode(e.state.nodes, node); err != nil {
		e.fail("go_semantic_identity_conflict", path, err.Error())
		return false
	}
	return true
}

func (e *goSemanticExtractor) registerResolver(index map[string]string, resolver, nodeID, path string) {
	if old := index[resolver]; old != "" && old != nodeID {
		e.fail("go_semantic_identity_conflict", path, fmt.Sprintf("resolver %q maps to both %s and %s", resolver, old, nodeID))
		return
	}
	index[resolver] = nodeID
}

func (e *goSemanticExtractor) addRelation(kind, sourceID, targetID string, condition Condition, evidence []Evidence, generated bool) {
	if sourceID == "" || targetID == "" || len(evidence) == 0 {
		return
	}
	condition = canonicalCondition(condition)
	primary := evidence[0]
	identity := map[string]any{
		"condition": condition, "kind": kind, "profile_id": e.state.profile.ID,
		"source": sourceID, "target": targetID, "path": primary.Path,
		"span": goSemanticSpan(primary),
	}
	edge := Edge{
		ID: stableIDFromValue("edge", identity), Source: sourceID, Target: targetID, Kind: kind,
		Phase: "semantic", Environment: "any", ResolutionStatus: "resolved",
		ProfileID: e.state.profile.ID, Condition: condition, Precision: "exact",
		Generated: generated, Evidence: append([]Evidence(nil), evidence...),
	}
	if old, ok := e.state.edges[edge.ID]; ok && !goSemanticEqual(old, edge) {
		e.fail("go_semantic_identity_conflict", primary.Path, "conflicting semantic edge "+edge.ID)
		return
	}
	e.state.edges[edge.ID] = edge
}

func (e *goSemanticExtractor) addTypeUse(sourceID, targetID, specifier, status, precision string, condition Condition, evidence []Evidence, generated bool) {
	if sourceID == "" || targetID == "" || len(evidence) == 0 {
		return
	}
	condition = canonicalCondition(condition)
	primary := evidence[0]
	siteIdentity := map[string]any{
		"condition": condition, "kind": "type_use", "path": primary.Path,
		"profile_id": e.state.profile.ID, "source": sourceID,
		"span": goSemanticSpan(primary),
	}
	site := Site{
		ID: stableIDFromValue("site", siteIdentity), Source: sourceID, Kind: "type_use",
		Specifier: specifier, ResolutionStatus: status, TargetIDs: []string{targetID},
		ProfileID: e.state.profile.ID, Condition: condition, Precision: precision,
		Evidence: append([]Evidence(nil), evidence...),
	}
	if old, ok := e.state.sites[site.ID]; ok {
		if !goSemanticEqual(old, site) {
			e.fail("go_semantic_identity_conflict", primary.Path, "conflicting semantic site "+site.ID)
		}
		return
	}
	e.state.sites[site.ID] = site
	edgeIdentity := map[string]any{"kind": "type_uses", "site_id": site.ID, "target": targetID}
	edge := Edge{
		ID: stableIDFromValue("edge", edgeIdentity), Source: sourceID, Target: targetID,
		Kind: "type_uses", SiteID: site.ID, Phase: "semantic", Environment: "any",
		ResolutionStatus: status, ProfileID: e.state.profile.ID, Condition: condition,
		Precision: precision, Generated: generated, Evidence: append([]Evidence(nil), evidence...),
	}
	if old, ok := e.state.edges[edge.ID]; ok && !goSemanticEqual(old, edge) {
		e.fail("go_semantic_identity_conflict", primary.Path, "conflicting semantic edge "+edge.ID)
		return
	}
	e.state.edges[edge.ID] = edge
}

func goSemanticSpan(evidence Evidence) map[string]any {
	return map[string]any{
		"start_line": evidence.StartLine, "start_column": evidence.StartColumn,
		"end_line": evidence.EndLine, "end_column": evidence.EndColumn,
	}
}

func goSemanticEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func (e *goSemanticExtractor) accountSemanticSites() {
	counts := map[string]int{}
	for siteID, site := range e.state.sites {
		if e.beforeSites[siteID] {
			continue
		}
		if len(site.Evidence) == 0 || site.Evidence[0].Kind != "semantic" || site.Evidence[0].Path == "" {
			e.fail("go_semantic_ledger", "", "semantic site "+siteID+" has no primary semantic evidence")
			continue
		}
		counts[site.Evidence[0].Path]++
	}
	indices := map[string][]int{}
	for index := range e.state.files {
		path := e.state.files[index].Path
		indices[path] = append(indices[path], index)
	}
	paths := make([]string, 0, len(counts))
	for path := range counts {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		matches := indices[path]
		if len(matches) != 1 {
			e.fail("go_semantic_ledger", path, fmt.Sprintf("semantic site ledger found %d file completions, want 1", len(matches)))
			continue
		}
		completion := &e.state.files[matches[0]]
		completion.DiscoveredSites += counts[path]
		completion.EmittedSites += counts[path]
	}
}

func (e *goSemanticExtractor) fail(code, path, message string) {
	e.complete = false
	for _, diagnostic := range e.state.diagnostics {
		if diagnostic.Code == code && diagnostic.Path == path && diagnostic.Message == message {
			return
		}
	}
	e.state.diagnostics = append(e.state.diagnostics, Diagnostic{
		Code: code, Severity: "warning", Message: message, ProfileID: e.state.profile.ID,
		Path: path, Recoverable: true,
	})
}
