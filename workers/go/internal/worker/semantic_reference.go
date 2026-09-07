package worker

import (
	"go/token"
	"go/types"
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
				c.declareSymbol(typed, "function", resolver)
			}
		case *types.Var:
			if typed.Exported() {
				c.declareSymbol(typed, "variable", resolver)
			}
		case *types.Const:
			if typed.Exported() {
				c.declareSymbol(typed, "constant", resolver)
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
		c.declareSymbol(method, "method", goSemanticMethodResolver(ownerResolver, method.Name(), pointer))
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
			c.declareSymbol(field, "field", ownerResolver+"."+field.Name())
		}
	case *types.Interface:
		for index := 0; index < underlying.NumExplicitMethods(); index++ {
			method := underlying.ExplicitMethod(index)
			if method == nil || !method.Exported() || method.Pkg() != c.reference.Types {
				continue
			}
			c.declareSymbol(method, "method", goSemanticMethodResolver(ownerResolver, method.Name(), false))
		}
	}
}

func (c *goSemanticReferenceContext) declareSymbol(object types.Object, symbolKind, resolver string) string {
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
	referenced := map[string]bool{}
	for _, site := range e.state.sites {
		referenced[site.Source] = true
		for _, targetID := range site.TargetIDs {
			referenced[targetID] = true
		}
	}
	for _, edge := range e.state.edges {
		referenced[edge.Source] = true
		referenced[edge.Target] = true
	}
	for nodeID := range e.referenceNodeIDs {
		if !referenced[nodeID] {
			delete(e.state.nodes, nodeID)
		}
	}
}
