package worker

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
)

// goSemanticReferenceContext registers the canonical node identities of an
// in-repo dependency that the package-scope loader satisfied from export data
// (or from a source load without bodies). Symbol and type identities are
// string-keyed on the package locator and the resolver, never on positions or
// go/types pointers, so the identities derived here are exactly the ones the
// unit that owns the dependency emits for its own declarations. The reference
// context emits nodes only: declarations, members and implements relations of
// the dependency belong to its owning unit.
type goSemanticReferenceContext struct {
	extractor      *goSemanticExtractor
	reference      goReferencePackage
	stub           goTypedPackage
	packageLocator string
	moduleDir      string
	structOwners   map[*types.Struct]*types.TypeName
	// locations maps a declaration key (see goReferenceDeclarationLocations)
	// to the span of its declaring identifier, as the owning unit records it.
	locations map[string]goSemanticSourceSpanKey
}

// registerReferencePackages runs before any target context declares its own
// objects so that resolver lookups, imported-interface records and SSA
// candidate mapping observe the dependency identities.
func (e *goSemanticExtractor) registerReferencePackages() {
	references := append([]goReferencePackage(nil), e.state.goPackages.ReferencePackages...)
	sort.SliceStable(references, func(left, right int) bool {
		if references[left].ModuleRelativeDir != references[right].ModuleRelativeDir {
			return references[left].ModuleRelativeDir < references[right].ModuleRelativeDir
		}
		return references[left].ID < references[right].ID
	})
	for _, reference := range references {
		if reference.Types == nil || reference.Types.Scope() == nil {
			continue
		}
		stub := goTypedPackage{
			ID: reference.ID, PkgPath: reference.PkgPath, Name: reference.Name,
			ModulePath: reference.ModulePath, ModuleRelativeDir: reference.ModuleRelativeDir,
		}
		context := &goSemanticReferenceContext{
			extractor: e, reference: reference, stub: stub,
			packageLocator: goSemanticPackageLocator(stub),
			moduleDir:      filepath.Clean(filepath.Join(e.state.root, filepath.FromSlash(cleanSlash(reference.ModuleRelativeDir)))),
			locations:      goReferenceDeclarationLocations(e.state.root, reference.CompiledGoFiles),
		}
		context.declare()
	}
}

func (c *goSemanticReferenceContext) declare() {
	scope := c.reference.Types.Scope()
	names := append([]string(nil), scope.Names()...)
	sort.Strings(names)
	c.indexStructOwners(scope, names)
	packagePath := c.reference.Types.Path()
	for _, name := range names {
		object := scope.Lookup(name)
		if object == nil || object.Pkg() != c.reference.Types {
			continue
		}
		resolver := packagePath + "." + name
		switch typed := object.(type) {
		case *types.TypeName:
			// Unexported types stay reachable through exported constructors, so
			// their exported members need identities as well.
			nodeID := c.declareType(typed, resolver)
			if nodeID != "" {
				c.declareMembers(typed, resolver)
			}
		case *types.Func:
			if typed.Exported() {
				c.declareSymbol(typed, "function", resolver, name)
			}
		case *types.Var:
			if typed.Exported() {
				c.declareSymbol(typed, "variable", resolver, name)
			}
		case *types.Const:
			if typed.Exported() {
				c.declareSymbol(typed, "constant", resolver, name)
			}
		}
	}
}

// indexStructOwners decides which named type declares a struct literal. The
// owning unit attaches fields to the type whose declaration spells the struct
// (`type B struct{...}`), never to `type A B`, which shares the same
// *types.Struct. Without syntax the declaring type is the candidate declared
// closest before the first field in the shared file set.
func (c *goSemanticReferenceContext) indexStructOwners(scope *types.Scope, names []string) {
	candidates := map[*types.Struct][]*types.TypeName{}
	for _, name := range names {
		typed, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || typed.IsAlias() || typed.Pkg() != c.reference.Types {
			continue
		}
		named, ok := typed.Type().(*types.Named)
		if !ok {
			continue
		}
		if structType, ok := named.Underlying().(*types.Struct); ok {
			candidates[structType] = append(candidates[structType], typed)
		}
	}
	c.structOwners = make(map[*types.Struct]*types.TypeName, len(candidates))
	for structType, owners := range candidates {
		if len(owners) == 1 {
			c.structOwners[structType] = owners[0]
			continue
		}
		if structType.NumFields() == 0 {
			continue
		}
		firstField := structType.Field(0).Pos()
		if firstField == token.NoPos {
			continue
		}
		var best *types.TypeName
		for _, owner := range owners {
			if owner.Pos() == token.NoPos || owner.Pos() >= firstField {
				continue
			}
			if best == nil || owner.Pos() > best.Pos() {
				best = owner
			}
		}
		if best != nil {
			c.structOwners[structType] = best
		}
	}
}

func (c *goSemanticReferenceContext) declareType(object *types.TypeName, resolver string) string {
	typeKind := goSemanticTypeKind(object)
	identity := map[string]any{
		"language": "go", "package_locator": c.packageLocator,
		"type_kind": typeKind, "resolver_identity": resolver,
	}
	nodeID := stableIDFromValue("type", identity)
	nodeValue := Node{
		ID: nodeID, Kind: "type", Locator: "go-type:" + resolver,
		DisplayName: object.Name(),
		Properties: map[string]any{
			"language": "go", "package_locator": c.packageLocator,
			"type_kind": typeKind, "canonical_identity": identity,
		},
	}
	c.addLocation(nodeValue.Properties, object.Name())
	if !c.extractor.addNode(nodeValue, "") {
		return ""
	}
	extractor := c.extractor
	extractor.referenceNodeIDs[nodeID] = true
	extractor.typeNodesByObject[object] = nodeID
	extractor.nodeResolvers[nodeID] = resolver
	extractor.registerResolver(extractor.typeNodesByResolver, resolver, nodeID, "")
	extractor.registerTypeOrigin(nodeID, c.stub)
	if named := goSemanticNamedFromType(object.Type()); named != nil && named.Obj() == object {
		if _, exists := extractor.referenceNamedTypes[nodeID]; !exists {
			record := goSemanticNamedType{
				nodeID: nodeID, named: named, moduleDir: c.moduleDir, packagePath: c.reference.PkgPath,
				condition: AlwaysCondition(),
			}
			if interfaceType, ok := named.Underlying().(*types.Interface); ok {
				record.interfaceType = interfaceType.Complete()
			}
			extractor.referenceNamedTypes[nodeID] = record
		}
	}
	return nodeID
}

func (c *goSemanticReferenceContext) declareMembers(object *types.TypeName, ownerResolver string) {
	if object.IsAlias() {
		// An alias declares no members of its own; they belong to the aliased
		// type's declaration, which is registered under that type's resolver.
		return
	}
	named, ok := object.Type().(*types.Named)
	if !ok {
		return
	}
	for index := 0; index < named.NumMethods(); index++ {
		method := named.Method(index)
		if method == nil || !method.Exported() || method.Pkg() != c.reference.Types {
			continue
		}
		signature, ok := method.Type().(*types.Signature)
		if !ok || signature.Recv() == nil {
			continue
		}
		_, pointer := goSemanticReceiverNamed(signature.Recv().Type())
		c.declareSymbol(method, "method", goSemanticMethodResolver(ownerResolver, method.Name(), pointer), object.Name()+"."+method.Name())
	}
	switch underlying := named.Underlying().(type) {
	case *types.Struct:
		if c.structOwners[underlying] != object {
			return
		}
		for index := 0; index < underlying.NumFields(); index++ {
			field := underlying.Field(index)
			if field == nil || !field.Exported() || field.Pkg() != c.reference.Types {
				continue
			}
			c.declareSymbol(field, "field", ownerResolver+"."+field.Name(), object.Name()+"."+field.Name())
		}
	case *types.Interface:
		for index := 0; index < underlying.NumExplicitMethods(); index++ {
			method := underlying.ExplicitMethod(index)
			if method == nil || !method.Exported() || method.Pkg() != c.reference.Types {
				continue
			}
			c.declareSymbol(method, "method", goSemanticMethodResolver(ownerResolver, method.Name(), false), object.Name()+"."+method.Name())
		}
	}
}

func (c *goSemanticReferenceContext) declareSymbol(object types.Object, symbolKind, resolver, locationKey string) string {
	identity := map[string]any{
		"language": "go", "package_locator": c.packageLocator,
		"symbol_kind": symbolKind, "identity_kind": "named", "resolver_identity": resolver,
	}
	nodeID := stableIDFromValue("symbol", identity)
	nodeValue := Node{
		ID: nodeID, Kind: "symbol", Locator: "go-symbol:" + resolver, DisplayName: object.Name(),
		Properties: map[string]any{
			"language": "go", "package_locator": c.packageLocator,
			"symbol_kind": symbolKind, "canonical_identity": identity,
		},
	}
	c.addLocation(nodeValue.Properties, locationKey)
	if !c.extractor.addNode(nodeValue, "") {
		return ""
	}
	extractor := c.extractor
	extractor.referenceNodeIDs[nodeID] = true
	extractor.symbolNodesByObject[object] = nodeID
	extractor.nodeResolvers[nodeID] = resolver
	extractor.registerResolver(extractor.symbolNodesByResolver, resolver, nodeID, "")
	extractor.registerSymbolOrigin(nodeID, c.stub)
	return nodeID
}

// pruneReferenceNodes drops reference identities that no retained site or
// edge of this unit points at. The owning unit emits the complete declaration
// set; this unit only needs the targets it actually references so that its
// graph is a subset of the module-whole-program graph rather than a superset.
func (e *goSemanticExtractor) pruneReferenceNodes() {
	if len(e.referenceNodeIDs) == 0 {
		return
	}
	referenced := e.state.referencedNodeIDs()
	for nodeID := range e.referenceNodeIDs {
		if !referenced[nodeID] {
			delete(e.state.nodes, nodeID)
		}
	}
}

// referencedNodeIDs is the set of node IDs that a retained site or edge of
// this unit names as an endpoint. The protocol validator requires each of them
// to be declared in the same stream.
func (s *scannerState) referencedNodeIDs() map[string]bool {
	referenced := make(map[string]bool, 2*len(s.edges)+len(s.sites))
	for _, site := range s.sites {
		referenced[site.Source] = true
		for _, targetID := range site.TargetIDs {
			referenced[targetID] = true
		}
	}
	for _, edge := range s.edges {
		referenced[edge.Source] = true
		referenced[edge.Target] = true
	}
	return referenced
}

// addLocation gives a reference node the source_path and source_span that the
// unit owning the declaration records (#596). The core rejects a node whose
// properties differ between units, so a reference node must carry exactly the
// owner's values, or nothing when the declaration cannot be located.
func (c *goSemanticReferenceContext) addLocation(properties map[string]any, key string) {
	location, ok := c.locations[key]
	if !ok {
		return
	}
	properties["source_path"] = location.path
	properties["source_span"] = map[string]any{
		"start_line": location.startLine, "start_column": location.startColumn,
		"end_line": location.endLine, "end_column": location.endColumn,
	}
}

// goReferenceDeclarationLocations parses a dependency's compiled files and
// records the span of every package-scope declaring identifier. Export data
// only keeps line numbers, so positions are taken from the source the owning
// unit parses, with the same unadjusted (//line-free) positions and the same
// repository-relative paths. Keys are the package-scope name, or
// "Type.Member" for methods, struct fields and interface methods. A key
// declared twice is dropped rather than guessed.
func goReferenceDeclarationLocations(root string, compiledGoFiles []string) map[string]goSemanticSourceSpanKey {
	locations := map[string]goSemanticSourceSpanKey{}
	ambiguous := map[string]bool{}
	for _, file := range compiledGoFiles {
		confined, ok := confinedMetadataFile(root, file)
		if !ok {
			continue
		}
		source, err := os.ReadFile(confined)
		if err != nil {
			continue
		}
		fset := token.NewFileSet()
		syntax, _ := parser.ParseFile(fset, confined, source, parser.AllErrors|parser.SkipObjectResolution)
		if syntax == nil {
			continue
		}
		path := relativePath(root, confined)
		record := func(key string, identifier *ast.Ident) {
			if identifier == nil || identifier.Name == "_" || ambiguous[key] {
				return
			}
			if _, exists := locations[key]; exists {
				delete(locations, key)
				ambiguous[key] = true
				return
			}
			start := fset.PositionFor(identifier.Pos(), false)
			end := fset.PositionFor(identifier.End(), false)
			locations[key] = goSemanticSourceSpanKey{
				path: path, startLine: start.Line, startColumn: start.Column,
				endLine: end.Line, endColumn: end.Column,
			}
		}
		for _, declaration := range syntax.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				if typed.Name == nil || (typed.Recv == nil && typed.Name.Name == "init") {
					continue
				}
				if typed.Recv == nil {
					record(typed.Name.Name, typed.Name)
					continue
				}
				if len(typed.Recv.List) != 1 {
					continue
				}
				if receiver := goReferenceTypeIdentifier(typed.Recv.List[0].Type); receiver != nil {
					record(receiver.Name+"."+typed.Name.Name, typed.Name)
				}
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if spec.Name == nil {
							continue
						}
						record(spec.Name.Name, spec.Name)
						recordGoReferenceMembers(spec, record)
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							if name != nil {
								record(name.Name, name)
							}
						}
					}
				}
			}
		}
	}
	return locations
}

// recordGoReferenceMembers records the members a type spec spells directly,
// matching the owning unit's declareTypeMembers.
func recordGoReferenceMembers(spec *ast.TypeSpec, record func(string, *ast.Ident)) {
	owner := spec.Name.Name
	var fields *ast.FieldList
	switch typed := ast.Unparen(spec.Type).(type) {
	case *ast.StructType:
		fields = typed.Fields
	case *ast.InterfaceType:
		fields = typed.Methods
	}
	if fields == nil {
		return
	}
	_, isInterface := ast.Unparen(spec.Type).(*ast.InterfaceType)
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			if isInterface {
				continue
			}
			// An embedded field is declared by its type name.
			if identifier := goReferenceTypeIdentifier(field.Type); identifier != nil {
				record(owner+"."+identifier.Name, identifier)
			}
			continue
		}
		for _, name := range field.Names {
			if name != nil {
				record(owner+"."+name.Name, name)
			}
		}
	}
}

// goReferenceTypeIdentifier returns the identifier naming a receiver or an
// embedded field type: T, *T, pkg.T, T[P] and (T).
func goReferenceTypeIdentifier(expression ast.Expr) *ast.Ident {
	for {
		switch typed := expression.(type) {
		case *ast.Ident:
			return typed
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.StarExpr:
			expression = typed.X
		case *ast.IndexExpr:
			expression = typed.X
		case *ast.IndexListExpr:
			expression = typed.X
		case *ast.SelectorExpr:
			return typed.Sel
		default:
			return nil
		}
	}
}
