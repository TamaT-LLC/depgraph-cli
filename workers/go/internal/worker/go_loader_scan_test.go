package worker

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

const goLoaderCallGraphModule = "example.com/cg"

// goLoaderCallGraphFixture is the "closure-from-dependency" shape of the plan:
// the owned package calls a dependency interface (invoke), a dependency
// function value with a repository-specific signature, and a closure that the
// dependency returns. Only the last one needs dependency bodies.
func goLoaderCallGraphFixture(t *testing.T) string {
	t.Helper()
	return goLoaderTestFixture(t, map[string]string{
		"go.mod": "module " + goLoaderCallGraphModule + "\n\ngo 1.26.1\n",
		"shape/shape.go": `package shape

type Token struct{}

type Shape interface{ Area() int }

type Square struct{ Side int }

func (s Square) Area() int { return s.Side * s.Side }

type Circle struct{ Radius int }

func (c *Circle) Area() int { return 3 * c.Radius * c.Radius }

func One(Token) int { return 1 }

func Two(Token) int { return 2 }

func Pick(flag bool) func(Token) int {
	if flag {
		return Two
	}
	return One
}

func Maker() func() Token { return func() Token { return Token{} } }

func New(side int) Shape { return Square{Side: side} }
`,
		"use/use.go": `package use

import "example.com/cg/shape"

type Local struct{}

func (Local) Area() int { return 1 }

func Total(shapes ...shape.Shape) int {
	total := 0
	for _, s := range shapes {
		total += s.Area()
	}
	return total
}

func Picked(flag bool) int {
	target := shape.Pick(flag)
	token := shape.Maker()()
	return target(token)
}

func Describe() int { return Total(shape.New(2), Local{}) + Picked(true) }
`,
		"use/use_external_test.go": `package use_test

import (
	"testing"

	"example.com/cg/shape"
	"example.com/cg/use"
)

func TestDescribe(t *testing.T) {
	if use.Total(shape.Square{Side: 1}) != 1 || use.Describe() == 0 {
		t.Fatal("unexpected")
	}
}
`,
		"cmd/app/main.go": `package main

import "example.com/cg/use"

func main() { _ = use.Describe() }
`,
	})
}

func goLoaderCallGraphRequest() AnalysisUnitRequest {
	return AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:use",
		Adapter:            AdapterName,
		UnitRoot:           ".",
		SourcePaths:        []string{"use/use.go", "use/use_external_test.go"},
		Stage:              AnalysisUnitStageSemantic,
		ContextPaths:       []string{"cmd/app/main.go", "shape/shape.go", "use/use.go", "use/use_external_test.go"},
		ChunkID:            "use",
		ChunkCount:         1,
		ContextFingerprint: "use-context",
	}
}

func goLoaderScanUnit(t *testing.T, root string, options scanOptions) Result {
	t.Helper()
	request := goLoaderCallGraphRequest()
	if err := request.Validate(); err != nil {
		t.Fatalf("request.Validate() error = %v", err)
	}
	result, err := scanWithOptions(root, nil, &request, nil, options)
	if err != nil {
		t.Fatalf("scanWithOptions(%+v) error = %v", options, err)
	}
	if !containsString(result.Coverage.Completeness, "semantic-complete") || containsString(result.Coverage.Reasons, "go-semantic-incomplete") || containsString(result.Coverage.Reasons, "go-packages-parser-fallback") {
		t.Fatalf("scan(%+v) coverage = %+v, diagnostics = %+v", options, result.Coverage, result.Diagnostics)
	}
	return result
}

func goLoaderSiteSummary(site Site) string {
	return strings.Join([]string{site.Kind, site.ResolutionStatus, site.Precision, site.Reason, strings.Join(site.TargetIDs, ",")}, "|")
}

func goLoaderSitesByID(result Result) map[string]Site {
	sites := make(map[string]Site, len(result.Sites))
	for _, site := range result.Sites {
		sites[site.ID] = site
	}
	return sites
}

func goLoaderNodesByID(result Result) map[string]Node {
	nodes := make(map[string]Node, len(result.Nodes))
	for _, node := range result.Nodes {
		nodes[node.ID] = node
	}
	return nodes
}

func goLoaderSiteAt(t *testing.T, result Result, sourceID, path string, line int, status string) Site {
	t.Helper()
	var matches []Site
	for _, site := range result.Sites {
		if site.Kind == "call" && site.ResolutionStatus == status && site.Source == sourceID &&
			len(site.Evidence) > 0 && site.Evidence[0].Path == path && site.Evidence[0].StartLine == line {
			matches = append(matches, site)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("%s call %s:%d from %s matches = %d, want 1; sites=%+v", status, path, line, sourceID, len(matches), result.Sites)
	}
	return matches[0]
}

func goLoaderCalleeNames(graph *callgraph.Graph, callerSuffix string, invoke bool) []string {
	names := map[string]bool{}
	for function, node := range graph.Nodes {
		if function == nil || !strings.HasSuffix(function.String(), callerSuffix) {
			continue
		}
		for _, edge := range node.Out {
			if edge == nil || edge.Site == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}
			if edge.Site.Common().IsInvoke() != invoke || edge.Site.Common().StaticCallee() != nil {
				continue
			}
			names[edge.Callee.Func.String()] = true
		}
	}
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// TestGoPackageScopeCallGraphRestoresDependencyMethodSets pins the reason the
// package scope has its own CHA driver: over an export-data program, stock CHA
// enumerates the method sets of syntactic packages only, so a dependency type
// that the targets never instantiate (*Circle) disappears from the invoke
// candidates. The package-scope driver restores it from declarations while
// still, by construction, knowing nothing about closures in dependencies.
func TestGoPackageScopeCallGraphRestoresDependencyMethodSets(t *testing.T) {
	root := goLoaderCallGraphFixture(t)
	modules := goLoaderTestModules(t, root)
	session := goLoaderTestSession(t, root, "")
	result := session.loadPackageScope(goLoaderScope{
		Module: goLoaderTestModule(t, modules, "."), Modules: modules, Targets: []goLoaderTargetSpec{{Dir: "use"}},
	}, nil)
	if result.Status != "loaded" {
		t.Fatalf("status = %q:\n%s", result.Status, goLoaderDiagnosticSummary(result.Diagnostics))
	}
	build, err := buildGoSSA(result.SSAInput)
	if err != nil {
		t.Fatalf("buildGoSSA() error = %v", err)
	}
	if build.scope != goSSAProgramScopePackage || build.complete {
		t.Fatalf("package-scope build = scope %q complete %t", build.scope, build.complete)
	}
	for _, pkg := range build.program.AllPackages() {
		syntactic := goSSAPackageIsSyntactic(pkg)
		if isTarget := strings.HasPrefix(pkg.Pkg.Path(), goLoaderCallGraphModule+"/use"); syntactic != isTarget {
			t.Fatalf("package %s syntactic = %t, want %t (only targets carry bodies)", pkg.Pkg.Path(), syntactic, isTarget)
		}
	}

	// buildGoCHAGraph selects the driver by declared scope and inlines the
	// synthetic pointer wrappers in both cases.
	stock, err := buildGoCHAGraph(build.program, goSSAProgramScopeWholeProgram)
	if err != nil {
		t.Fatalf("stock CHA error = %v", err)
	}
	scoped, err := buildGoCHAGraph(build.program, goSSAProgramScopePackage)
	if err != nil {
		t.Fatalf("package-scope CHA error = %v", err)
	}
	wantInvoke := []string{
		"(*" + goLoaderCallGraphModule + "/shape.Circle).Area",
		"(" + goLoaderCallGraphModule + "/shape.Square).Area",
		"(" + goLoaderCallGraphModule + "/use.Local).Area",
	}
	if got := goLoaderCalleeNames(scoped, "/use.Total", true); !reflect.DeepEqual(got, wantInvoke) {
		t.Fatalf("package-scope invoke candidates = %v, want %v", got, wantInvoke)
	}
	if got := goLoaderCalleeNames(stock, "/use.Total", true); reflect.DeepEqual(got, wantInvoke) {
		t.Fatalf("stock CHA unexpectedly enumerated the never-instantiated dependency implementer: %v", got)
	} else if !containsString(got, "("+goLoaderCallGraphModule+"/shape.Square).Area") {
		t.Fatalf("stock CHA lost even the materialised implementer: %v", got)
	}
	// Function values declared by the dependency are enumerable from export
	// data; the closure returned by Maker is not, in either driver.
	wantFunctions := []string{goLoaderCallGraphModule + "/shape.One", goLoaderCallGraphModule + "/shape.Two"}
	for name, graph := range map[string]*callgraph.Graph{"stock": stock, "package-scope": scoped} {
		got := goLoaderCalleeNames(graph, "/use.Picked", false)
		if !reflect.DeepEqual(got, wantFunctions) {
			t.Fatalf("%s dynamic function-value candidates = %v, want %v", name, got, wantFunctions)
		}
	}
	// The restored universe never invents bodies: every dependency callee is a
	// declaration-only function, and every call site belongs to a target.
	for function, node := range scoped.Nodes {
		if function == nil {
			continue
		}
		if pkg := goSSAFunctionPackage(function); pkg != nil && !strings.HasPrefix(pkg.Path(), goLoaderCallGraphModule+"/use") && len(function.Blocks) > 0 && function.Synthetic == "" {
			t.Fatalf("dependency function %s carries a body in the package-scope program", function)
		}
		for _, edge := range node.Out {
			if edge.Caller == nil || edge.Caller.Func == nil || goSSAFunctionPackage(edge.Caller.Func) == nil {
				t.Fatalf("edge without a caller package: %+v", edge)
			}
			if !strings.HasPrefix(goSSAFunctionPackage(edge.Caller.Func).Path(), goLoaderCallGraphModule+"/use") {
				t.Fatalf("call site outside the targets: %s -> %s", edge.Caller.Func, edge.Callee.Func)
			}
		}
	}
	// Same declared program, same mapping: the index the semantic stage builds
	// from the package-scope graph keys every Total/Picked site.
	index := indexGoSSAGraph(result.SSAInput, scoped)
	if len(index.sites) == 0 || len(index.targets) == 0 {
		t.Fatalf("package-scope graph index is empty: %+v", index)
	}
	var totalFunction *ssa.Function
	for function := range scoped.Nodes {
		if function != nil && function.String() == goLoaderCallGraphModule+"/use.Total" {
			totalFunction = function
		}
	}
	if totalFunction == nil || len(totalFunction.Blocks) == 0 {
		t.Fatal("target function Total has no body in the package-scope program")
	}
}

// TestGoLoaderPackageScopeScanRunsCHAOverDeclaredScopeWithSharedIdentity runs
// the same semantic analysis unit through the module-whole-program loader and
// the package-scope hybrid loader and checks the plan's contract: CHA only with
// a declared program scope, interface invokes keep candidates/overapprox,
// function values resolve to export-data declarations, closures defined in
// dependencies stay unresolved, and every node, edge and site identity that
// both runs emit is byte-identical.
func TestGoLoaderPackageScopeScanRunsCHAOverDeclaredScopeWithSharedIdentity(t *testing.T) {
	root := goLoaderCallGraphFixture(t)
	whole := goLoaderScanUnit(t, root, scanOptions{})
	scoped := goLoaderScanUnit(t, root, scanOptions{loaderMode: goLoaderModePackage, loaderTargets: []goLoaderTargetSpec{{Dir: "use"}}})

	// Profile: the declaration is explicit and the base identity is shared
	// because the dependency snapshot comes from the module-wide listing.
	wantScoped := map[string]string{
		"analysis_loader_mode":                 "package",
		"analysis_scope":                       "target_packages",
		"go_loader_program_scope":              "package-with-declaration-deps",
		"go_call_graph_program_scope":          "package-with-declaration-deps",
		"go_call_graph_effective_algorithms":   "cha",
		"go_call_graph_vta_status":             "not-requested",
		"go_loader_syntax_equals_targets":      "true",
		"go_loader_target_packages":            "2",
		"go_loader_syntax_packages":            "2",
		"go_loader_reference_packages_in_repo": "1",
	}
	for key, value := range wantScoped {
		if got := scoped.Profile.Properties[key]; got != value {
			t.Fatalf("package-scope property %s = %q, want %q", key, got, value)
		}
	}
	if got := whole.Profile.Properties["analysis_scope"]; got != "full_module" {
		t.Fatalf("module-whole-program analysis_scope = %q, want full_module", got)
	}
	// The whole-program stream stays byte-identical to earlier workers: the
	// scope declaration and the loader evidence appear only in package mode.
	for _, key := range []string{"go_call_graph_program_scope", "analysis_loader_mode", "go_loader_program_scope", "go_reference_fingerprint"} {
		if value, present := whole.Profile.Properties[key]; present {
			t.Fatalf("module-whole-program profile carries %s=%q", key, value)
		}
	}
	if scoped.Profile.ID != whole.Profile.ID {
		t.Fatalf("profile identity differs between loaders: %s vs %s", scoped.Profile.ID, whole.Profile.ID)
	}
	if scoped.Profile.Properties["go_dependency_snapshot_fingerprint"] != whole.Profile.Properties["go_dependency_snapshot_fingerprint"] || scoped.Profile.Properties["go_dependency_snapshot_fingerprint"] == "" {
		t.Fatalf("dependency snapshot differs between loaders: %q vs %q", scoped.Profile.Properties["go_dependency_snapshot_fingerprint"], whole.Profile.Properties["go_dependency_snapshot_fingerprint"])
	}

	// Interface invoke through a dependency interface: candidates/overapprox
	// from CHA, with the dependency methods mapped onto reference nodes that
	// carry exactly the identities the owning unit emits.
	total := semanticFindNamedNode(t, scoped, "symbol", "function", goLoaderCallGraphModule+"/use.Total")
	square := semanticFindNamedNode(t, scoped, "symbol", "method", goLoaderCallGraphModule+"/shape.(Square).Area")
	circle := semanticFindNamedNode(t, scoped, "symbol", "method", goLoaderCallGraphModule+"/shape.(*Circle).Area")
	local := semanticFindNamedNode(t, scoped, "symbol", "method", goLoaderCallGraphModule+"/use.(Local).Area")
	invoke := ssaTestCandidateSite(t, scoped, total.ID, "use/use.go", 12)
	ssaTestRequireCandidateContract(t, scoped, invoke, "cha", "interface", []string{square.ID, circle.ID, local.ID})
	if got := invoke.Evidence[0].Properties; got["program_scope"] != "package-with-declaration-deps" || got["selection_reason"] != "package_scope_declaration_deps" || got["fallback_reason"] != "not_requested" {
		t.Fatalf("package-scope invoke evidence = %+v", got)
	}
	wholeInvoke := ssaTestCandidateSite(t, whole, total.ID, "use/use.go", 12)
	if wholeInvoke.ID != invoke.ID || !reflect.DeepEqual(wholeInvoke.TargetIDs, invoke.TargetIDs) {
		t.Fatalf("invoke site identity differs: whole=%+v scoped=%+v", wholeInvoke, invoke)
	}
	if got, declared := wholeInvoke.Evidence[0].Properties["program_scope"]; declared {
		t.Fatalf("module-whole-program invoke evidence declared program_scope = %v", got)
	}
	for _, method := range []Node{square, circle} {
		if whole := semanticFindNamedNode(t, whole, "symbol", "method", semanticIdentity(t, method)["resolver_identity"].(string)); whole.ID != method.ID {
			t.Fatalf("reference node %s has a different identity in the whole-program run: %s", method.ID, whole.ID)
		}
	}

	// Function value from the dependency: export data declares One and Two,
	// so CHA still enumerates them without any dependency bodies.
	picked := semanticFindNamedNode(t, scoped, "symbol", "function", goLoaderCallGraphModule+"/use.Picked")
	one := semanticFindNamedNode(t, scoped, "symbol", "function", goLoaderCallGraphModule+"/shape.One")
	two := semanticFindNamedNode(t, scoped, "symbol", "function", goLoaderCallGraphModule+"/shape.Two")
	functionValue := ssaTestCandidateSite(t, scoped, picked.ID, "use/use.go", 20)
	ssaTestRequireCandidateContract(t, scoped, functionValue, "cha", "function_value", []string{one.ID, two.ID})
	wholeFunctionValue := ssaTestCandidateSite(t, whole, picked.ID, "use/use.go", 20)
	if wholeFunctionValue.ID != functionValue.ID || !reflect.DeepEqual(wholeFunctionValue.TargetIDs, functionValue.TargetIDs) {
		t.Fatalf("function-value site identity differs: whole=%+v scoped=%+v", wholeFunctionValue, functionValue)
	}

	// Closure defined in the dependency: whole-program CHA sees its body and
	// emits the closure candidate; the declared package scope has no body and
	// conservatively reports the dynamic site as unresolved, without failing
	// semantic completeness.
	closureCall := goLoaderSiteAt(t, scoped, picked.ID, "use/use.go", 19, "unresolved")
	if closureCall.Reason != "function_value_dispatch" || closureCall.Precision != "heuristic" || len(closureCall.TargetIDs) != 1 {
		t.Fatalf("dependency closure call = %+v", closureCall)
	}
	wholeClosureCall := ssaTestCandidateSite(t, whole, picked.ID, "use/use.go", 19)
	if wholeClosureCall.ID != closureCall.ID || len(wholeClosureCall.TargetIDs) != 1 {
		t.Fatalf("whole-program closure call = %+v, want one closure candidate with the same site identity", wholeClosureCall)
	}
	wholeNodes := goLoaderNodesByID(whole)
	if closure := wholeNodes[wholeClosureCall.TargetIDs[0]]; closure.Kind != "symbol" || semanticNodeKind(closure) != "closure" {
		t.Fatalf("whole-program closure candidate = %+v", closure)
	}
	if !containsString(scoped.Coverage.Reasons, "unresolved-sites") || scoped.Coverage.Unresolved != whole.Coverage.Unresolved+1 {
		t.Fatalf("coverage: scoped=%+v whole=%+v", scoped.Coverage, whole.Coverage)
	}

	// Static calls, both into the owned package and into the dependency, stay
	// exact with identical targets.
	describe := semanticFindNamedNode(t, scoped, "symbol", "function", goLoaderCallGraphModule+"/use.Describe")
	newShape := semanticFindNamedNode(t, scoped, "symbol", "function", goLoaderCallGraphModule+"/shape.New")
	staticTargets := map[string]bool{}
	for _, site := range scoped.Sites {
		if site.Kind == "call" && site.Source == describe.ID && site.ResolutionStatus == "resolved" {
			for _, target := range site.TargetIDs {
				staticTargets[target] = true
			}
		}
	}
	if !staticTargets[newShape.ID] || !staticTargets[total.ID] || !staticTargets[picked.ID] {
		t.Fatalf("static call targets of Describe = %v, want shape.New, Total and Picked", staticTargets)
	}

	// Graph identity: every site both runs emit has the same identity and,
	// except for the dependency closure call, the same classification.
	scopedSites, wholeSites := goLoaderSitesByID(scoped), goLoaderSitesByID(whole)
	if len(scopedSites) != len(wholeSites) {
		t.Fatalf("site count differs: scoped=%d whole=%d", len(scopedSites), len(wholeSites))
	}
	for id, site := range scopedSites {
		counterpart, ok := wholeSites[id]
		if !ok {
			t.Fatalf("package-scope site is missing from the whole-program run: %+v", site)
		}
		if id == closureCall.ID {
			continue
		}
		if goLoaderSiteSummary(site) != goLoaderSiteSummary(counterpart) {
			t.Fatalf("site %s differs:\n scoped=%s\n whole =%s", id, goLoaderSiteSummary(site), goLoaderSiteSummary(counterpart))
		}
	}
	// Edges (contains, declares, implements, calls, ...) are identical except
	// for the candidate edges of the dependency closure call.
	edgeKeys := func(result Result, skipSite string) []string {
		keys := make([]string, 0, len(result.Edges))
		for _, edge := range result.Edges {
			if edge.SiteID == skipSite {
				continue
			}
			keys = append(keys, fmt.Sprintf("%s|%s|%s|%s|%s|%s", edge.Kind, edge.Phase, edge.Source, edge.Target, edge.ResolutionStatus, edge.Precision))
		}
		sort.Strings(keys)
		return keys
	}
	if scopedEdges, wholeEdges := edgeKeys(scoped, closureCall.ID), edgeKeys(whole, closureCall.ID); !reflect.DeepEqual(scopedEdges, wholeEdges) {
		t.Fatalf("edge sets differ:\n scoped=%s\n whole =%s", strings.Join(scopedEdges, "\n        "), strings.Join(wholeEdges, "\n        "))
	}
	// Implements relations against a dependency interface resolve to the same
	// interface type node in both runs.
	shapeType := semanticFindNamedNode(t, scoped, "type", "interface", goLoaderCallGraphModule+"/shape.Shape")
	if wholeShape := semanticFindNamedNode(t, whole, "type", "interface", goLoaderCallGraphModule+"/shape.Shape"); wholeShape.ID != shapeType.ID {
		t.Fatalf("interface identity differs: %s vs %s", shapeType.ID, wholeShape.ID)
	}
	localType := semanticFindNamedNode(t, scoped, "type", "struct", goLoaderCallGraphModule+"/use.Local")
	implements := false
	for _, edge := range scoped.Edges {
		if edge.Kind == "implements" && edge.Source == localType.ID && edge.Target == shapeType.ID {
			implements = true
		}
	}
	if !implements {
		t.Fatalf("Local implements shape.Shape was not emitted in package scope: %+v", scoped.Edges)
	}
	// Nodes: the package scope emits a subset of the whole-program nodes, the
	// owned package's declarations are complete, and only referenced
	// dependency identities survive pruning.
	scopedNodes := goLoaderNodesByID(scoped)
	for id, node := range scopedNodes {
		counterpart, ok := wholeNodes[id]
		if !ok {
			t.Fatalf("package-scope node is missing from the whole-program run: %+v", node)
		}
		if counterpart.Kind != node.Kind || counterpart.Locator != node.Locator {
			t.Fatalf("node %s differs: scoped=%+v whole=%+v", id, node, counterpart)
		}
	}
	useLocator := goSemanticPackageLocator(goTypedPackage{ID: goLoaderCallGraphModule + "/use", PkgPath: goLoaderCallGraphModule + "/use", ModulePath: goLoaderCallGraphModule, ModuleRelativeDir: "."})
	for id, node := range wholeNodes {
		if node.Properties["package_locator"] == useLocator {
			if _, ok := scopedNodes[id]; !ok {
				t.Fatalf("owned declaration missing from package scope: %+v", node)
			}
		}
	}
	referenced := map[string]bool{}
	for _, site := range scoped.Sites {
		referenced[site.Source] = true
		for _, target := range site.TargetIDs {
			referenced[target] = true
		}
	}
	for _, edge := range scoped.Edges {
		referenced[edge.Source] = true
		referenced[edge.Target] = true
	}
	shapeLocator := goSemanticPackageLocator(goTypedPackage{ID: goLoaderCallGraphModule + "/shape", PkgPath: goLoaderCallGraphModule + "/shape", ModulePath: goLoaderCallGraphModule, ModuleRelativeDir: "."})
	for id, node := range scopedNodes {
		if node.Properties["package_locator"] == shapeLocator && !referenced[id] {
			t.Fatalf("unreferenced dependency node survived pruning: %+v", node)
		}
	}
	// shape.Maker is called statically, so its symbol survives; shape.Circle is
	// only the receiver of a candidate method and its type node must be gone.
	if maker := semanticFindNamedNode(t, whole, "symbol", "function", goLoaderCallGraphModule+"/shape.Maker"); scopedNodes[maker.ID].ID == "" {
		t.Fatalf("referenced dependency function was pruned: %+v", maker)
	}
	if circleType := semanticFindNamedNode(t, whole, "type", "struct", goLoaderCallGraphModule+"/shape.Circle"); scopedNodes[circleType.ID].ID != "" {
		t.Fatalf("unreferenced dependency type survived pruning: %+v", circleType)
	}
	semanticAssertCoverageLedger(t, scoped)
	semanticAssertCoverageLedger(t, whole)
	t.Logf("package-scope scan: nodes=%d sites=%d edges=%d; whole-program: nodes=%d sites=%d edges=%d; loader: %s",
		len(scoped.Nodes), len(scoped.Sites), len(scoped.Edges), len(whole.Nodes), len(whole.Sites), len(whole.Edges),
		fmt.Sprintf("loaded=%s syntax=%s parsed_files=%s child_processes=%s", scoped.Profile.Properties["go_loader_loaded_packages"], scoped.Profile.Properties["go_loader_syntax_packages"], scoped.Profile.Properties["go_loader_parsed_files"], scoped.Profile.Properties["go_loader_child_processes"]))
}
