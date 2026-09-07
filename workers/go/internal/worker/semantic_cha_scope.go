package worker

import (
	"go/types"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/go/types/typeutil"
)

// goPackageScopeCallGraph computes the CHA call graph of a declared
// package-with-declaration-deps program.
//
// cha.CallGraph derives its universe from ssautil.AllFunctions, which
// enumerates the method sets of named types only for packages loaded from
// syntax (plus whatever the built bodies materialise as runtime types). In a
// package-scope program every dependency is non-syntactic, so a dependency
// type that implements an interface but is never instantiated by the targets
// themselves would silently vanish from the invoke candidates, making the
// "overapprox" candidate set narrower than the module-whole-program CHA over
// the same repository. This driver restores that universe from declarations:
// every package-level function plus the method sets of T and *T for every
// non-generic named type of every non-syntactic package. Only the targets have
// bodies, so only they contribute call sites; everything else is a callee.
func goPackageScopeCallGraph(program *ssa.Program) *callgraph.Graph {
	functions := ssautil.AllFunctions(program)
	for _, pkg := range program.AllPackages() {
		if pkg == nil || goSSAPackageIsSyntactic(pkg) {
			continue
		}
		for _, member := range pkg.Members {
			typ, ok := member.(*ssa.Type)
			if !ok || typ.Type() == nil || types.IsInterface(typ.Type()) {
				continue
			}
			named, ok := typ.Type().(*types.Named)
			if !ok || named.TypeParams() != nil || named.TypeArgs() != nil {
				continue
			}
			goPackageScopeMethods(program, named, functions)
			goPackageScopeMethods(program, types.NewPointer(named), functions)
		}
	}
	callees := goPackageScopeCallees(functions)
	graph := callgraph.New(nil)
	for function := range functions {
		node := graph.CreateNode(function)
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				site, ok := instruction.(ssa.CallInstruction)
				if !ok {
					continue
				}
				if callee := site.Common().StaticCallee(); callee != nil {
					callgraph.AddEdge(node, site, graph.CreateNode(callee))
					continue
				}
				for _, callee := range callees(site) {
					callgraph.AddEdge(node, site, graph.CreateNode(callee))
				}
			}
		}
	}
	return graph
}

// goSSAPackageIsSyntactic reports whether a package was created from syntax.
// go/ssa keeps that flag private, so it is recovered from the members: only a
// syntactic package can own a function with an AST (the synthetic package
// initialiser never has one). A syntactic package without any declared
// function is misclassified as declaration-only, which merely re-adds method
// sets that ssautil.AllFunctions already enumerated.
func goSSAPackageIsSyntactic(pkg *ssa.Package) bool {
	for _, member := range pkg.Members {
		if function, ok := member.(*ssa.Function); ok && function.Syntax() != nil {
			return true
		}
	}
	return false
}

// goPackageScopeMethods adds the concrete methods of one receiver type to the
// CHA universe. Methods of a non-syntactic package have no bodies; they exist
// only as callees so that invoke sites enumerate them.
func goPackageScopeMethods(program *ssa.Program, receiver types.Type, functions map[*ssa.Function]bool) {
	if types.IsInterface(receiver) {
		return
	}
	methodSet := program.MethodSets.MethodSet(receiver)
	for index := 0; index < methodSet.Len(); index++ {
		selection := methodSet.At(index)
		method, ok := selection.Obj().(*types.Func)
		if !ok || method.Signature() == nil || method.Signature().TypeParams() != nil {
			continue
		}
		if function := program.MethodValue(selection); function != nil {
			functions[function] = true
		}
	}
}

// goPackageScopeCallees resolves one call site over the given universe with
// the CHA rule set: invoke sites dispatch to every method of the same Id whose
// receiver implements the interface, static calls resolve to their callee, and
// dynamic function-value calls resolve to every address-taken function of the
// same signature. Package initialisers are never address-taken.
func goPackageScopeCallees(functions map[*ssa.Function]bool) func(site ssa.CallInstruction) []*ssa.Function {
	var bySignature typeutil.Map
	methodsByID := map[string][]*ssa.Function{}
	for function := range functions {
		if function == nil || function.Signature == nil {
			continue
		}
		if function.Signature.Recv() == nil {
			if function.Name() == "init" && function.Synthetic == "package initializer" {
				continue
			}
			existing, _ := bySignature.At(function.Signature).([]*ssa.Function)
			bySignature.Set(function.Signature, append(existing, function))
			continue
		}
		if object, ok := function.Object().(*types.Func); ok && object != nil {
			id := object.Id()
			methodsByID[id] = append(methodsByID[id], function)
		}
	}
	type interfaceMethod struct {
		iface *types.Interface
		id    string
	}
	memo := map[interfaceMethod][]*ssa.Function{}
	return func(site ssa.CallInstruction) []*ssa.Function {
		call := site.Common()
		switch {
		case call.IsInvoke():
			iface, ok := call.Value.Type().Underlying().(*types.Interface)
			if !ok || call.Method == nil {
				return nil
			}
			key := interfaceMethod{iface: iface, id: call.Method.Id()}
			methods, ok := memo[key]
			if !ok {
				for _, candidate := range methodsByID[key.id] {
					if types.Implements(candidate.Signature.Recv().Type(), iface) {
						methods = append(methods, candidate)
					}
				}
				memo[key] = methods
			}
			return methods
		case call.StaticCallee() != nil:
			return []*ssa.Function{call.StaticCallee()}
		default:
			if _, builtin := call.Value.(*ssa.Builtin); builtin {
				return nil
			}
			candidates, _ := bySignature.At(call.Signature()).([]*ssa.Function)
			return candidates
		}
	}
}
