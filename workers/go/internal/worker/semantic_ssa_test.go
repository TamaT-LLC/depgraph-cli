package worker

import (
	"bytes"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

const ssaLibrarySource = `package candidate

type Token struct{}
type Runner interface{ Run(Token) int }

type ValueRunner struct{}
func (ValueRunner) Run(Token) int { return 1 }

type PointerRunner struct{}
func (*PointerRunner) Run(Token) int { return 2 }

func InterfaceCall(r Runner, value Token) int {
	return r.Run(value)
}

func One(Token) int { return 1 }
func Two(Token) int { return 2 }

func FunctionCall(target func(Token) int, value Token) int {
	return target(value)
}
`

const ssaMainSource = `package main

type Token struct{}
type Runner interface{ Run(Token) int }
type Live struct{}
func (Live) Run(Token) int { return 1 }
type Dead struct{}
func (Dead) Run(Token) int { return 2 }

var selected Runner = Live{}

func InterfaceCall(r Runner, value Token) int {
	return r.Run(value)
}

func One(Token) int { return 1 }
func Two(Token) int { return 2 }

func FunctionCall(flag bool, value Token) int {
	target := One
	if flag {
		target = Two
	}
	return target(value)
}

func main() {
	value := Token{}
	_ = InterfaceCall(selected, value)
	_ = FunctionCall(false, value)
}
`

const ssaVTARefinementSource = `package candidate

type Token struct{}
type Runner interface{ Run(Token) int }

type Live struct{}
func (Live) Run(Token) int { return 1 }
type Dead struct{}
func (Dead) Run(Token) int { return 2 }

func RefinedCall(value Token) int {
	var runner Runner = Live{}
	return runner.Run(value)
}
`

func TestGoSSALibraryCHACandidates(t *testing.T) {
	root := ssaTestModule(t, "example.com/ssalibrary", map[string]string{
		"candidate/candidate.go": ssaLibrarySource,
	})
	result := ssaTestScan(t, root)

	interfaceCaller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssalibrary/candidate.InterfaceCall")
	valueMethod := semanticFindNamedNode(t, result, "symbol", "method", "example.com/ssalibrary/candidate.(ValueRunner).Run")
	pointerMethod := semanticFindNamedNode(t, result, "symbol", "method", "example.com/ssalibrary/candidate.(*PointerRunner).Run")
	interfaceSite := ssaTestCandidateSite(t, result, interfaceCaller.ID, "candidate/candidate.go", 13)
	ssaTestRequireCandidateContract(t, result, interfaceSite, "cha", "interface", []string{valueMethod.ID, pointerMethod.ID})

	functionCaller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssalibrary/candidate.FunctionCall")
	one := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssalibrary/candidate.One")
	two := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssalibrary/candidate.Two")
	functionSite := ssaTestCandidateSite(t, result, functionCaller.ID, "candidate/candidate.go", 20)
	ssaTestRequireCandidateContract(t, result, functionSite, "cha", "function_value", []string{one.ID, two.ID})

	if got := result.Profile.Properties["go_call_graph_library_partial"]; got != "cha" {
		t.Fatalf("library/partial call graph policy = %q, want cha", got)
	}
	semanticAssertCoverageLedger(t, result)
}

func TestGoSSAMainRTACandidatesOnlyReachableTargets(t *testing.T) {
	root := ssaTestModule(t, "example.com/ssamain", map[string]string{"main.go": ssaMainSource})
	result := ssaTestScan(t, root)

	interfaceCaller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssamain.InterfaceCall")
	live := semanticFindNamedNode(t, result, "symbol", "method", "example.com/ssamain.(Live).Run")
	dead := semanticFindNamedNode(t, result, "symbol", "method", "example.com/ssamain.(Dead).Run")
	interfaceSite := ssaTestCandidateSite(t, result, interfaceCaller.ID, "main.go", 13)
	ssaTestRequireCandidateContract(t, result, interfaceSite, "rta", "interface", []string{live.ID})
	if containsString(interfaceSite.TargetIDs, dead.ID) {
		t.Fatalf("RTA included unreachable Dead.Run in interface candidates: %+v", interfaceSite)
	}
	if interfaceSite.ResolutionStatus != "candidates" || len(interfaceSite.TargetIDs) != 1 {
		t.Fatalf("uncertain singleton call was promoted from candidates: %+v", interfaceSite)
	}

	functionCaller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssamain.FunctionCall")
	one := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssamain.One")
	two := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssamain.Two")
	functionSite := ssaTestCandidateSite(t, result, functionCaller.ID, "main.go", 24)
	ssaTestRequireCandidateContract(t, result, functionSite, "rta", "function_value", []string{one.ID, two.ID})

	if got := result.Profile.Properties["go_call_graph_main_test"]; got != "rta" {
		t.Fatalf("main/test call graph policy = %q, want rta", got)
	}
	semanticAssertCoverageLedger(t, result)
}

func TestGoSSAVTAOptInRefinesCHAAndIsDeterministic(t *testing.T) {
	root := ssaTestModule(t, "example.com/ssavta", map[string]string{
		"candidate/candidate.go": ssaVTARefinementSource,
	})
	defaultResult := ssaTestScan(t, root)
	caller := semanticFindNamedNode(t, defaultResult, "symbol", "function", "example.com/ssavta/candidate.RefinedCall")
	live := semanticFindNamedNode(t, defaultResult, "symbol", "method", "example.com/ssavta/candidate.(Live).Run")
	dead := semanticFindNamedNode(t, defaultResult, "symbol", "method", "example.com/ssavta/candidate.(Dead).Run")
	defaultSite := ssaTestCandidateSite(t, defaultResult, caller.ID, "candidate/candidate.go", 13)
	ssaTestRequireCandidateContract(t, defaultResult, defaultSite, "cha", "interface", []string{live.ID, dead.ID})
	if defaultResult.Profile.Properties["go_call_graph_requested"] != "rta-cha" ||
		defaultResult.Profile.Properties["go_call_graph_vta_status"] != "not-requested" {
		t.Fatalf("default profile unexpectedly enabled VTA: %+v", defaultResult.Profile)
	}

	t.Setenv("DEPGRAPH_PROFILE_CONFIG", `{"go_call_graph":"vta"}`)
	first := ssaTestScan(t, root)
	second := ssaTestScan(t, root)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("two VTA scans of the same root differ")
	}
	if first.Profile.ID == defaultResult.Profile.ID {
		t.Fatal("VTA opt-in reused the default profile identity")
	}
	vtaCaller := semanticFindNamedNode(t, first, "symbol", "function", "example.com/ssavta/candidate.RefinedCall")
	vtaLive := semanticFindNamedNode(t, first, "symbol", "method", "example.com/ssavta/candidate.(Live).Run")
	vtaSite := ssaTestCandidateSite(t, first, vtaCaller.ID, "candidate/candidate.go", 13)
	ssaTestRequireCandidateContract(t, first, vtaSite, "vta", "interface", []string{vtaLive.ID})
	if vtaSite.ResolutionStatus != "candidates" || vtaSite.Precision != "overapprox" {
		t.Fatalf("VTA singleton was promoted to exact: %+v", vtaSite)
	}
	for key, want := range map[string]string{
		"go_call_graph_requested": "vta", "go_call_graph_vta_status": "applied",
		"go_call_graph_effective_algorithms": "vta", "go_call_graph_vta_site_count": "1",
		"go_call_graph_vta_fallback_site_count": "0", "go_call_graph_vta_fallback_reasons": "",
	} {
		if got := first.Profile.Properties[key]; got != want {
			t.Fatalf("VTA profile property %s=%q, want %q: %+v", key, got, want, first.Profile.Properties)
		}
	}
}

func TestGoSSAVTAConstructionAndSelectionFailClosed(t *testing.T) {
	if graph, err := buildGoVTAGraph(nil); err == nil || graph != nil {
		t.Fatalf("buildGoVTAGraph(nil) = (%v, %v), want explicit failure", graph, err)
	}
	key := goSSACallKey{}
	rtaIndex := newGoSSAGraphIndex()
	rtaIndex.sites[key] = true
	pending := goSemanticPendingCall{context: &goSemanticPackage{typed: goTypedPackage{Name: "main"}}}
	algorithm, reason, fallback, _ := (*goSemanticExtractor)(nil).selectGoSSAIndex(
		pending, key, true, newGoSSAGraphIndex(), rtaIndex, true, newGoSSAGraphIndex(),
		"vta_construction_failed_fallback",
	)
	if algorithm != "rta" || reason != "main_or_test_program" || fallback != "vta_construction_failed_fallback" {
		t.Fatalf("VTA failure selection = (%q, %q, %q), want explicit RTA fallback", algorithm, reason, fallback)
	}
	evidence := goSSACandidateEvidence(goSemanticPendingCall{evidence: []Evidence{{
		Kind: "semantic", Properties: map[string]any{"dispatch": "interface"},
	}}}, algorithm, reason, fallback, 2, true)
	if len(evidence) != 1 || evidence[0].Properties["requested_algorithm"] != "vta" ||
		evidence[0].Properties["algorithm"] != "rta" || evidence[0].Properties["fallback_reason"] != fallback ||
		evidence[0].Properties["candidate_count"] != 2 {
		t.Fatalf("VTA fallback evidence is incomplete: %+v", evidence)
	}
	state := &scannerState{profile: Profile{Properties: map[string]string{}}}
	extractor := &goSemanticExtractor{state: state}
	extractor.recordSSAOutcome(&goSSAOutcome{
		requestedVTA: true, pendingSites: 1, fallbackSelections: 1,
		algorithms: map[string]bool{"rta": true}, fallbackReasons: map[string]bool{fallback: true},
	})
	if state.profile.Properties["go_call_graph_vta_status"] != "fallback" ||
		state.profile.Properties["go_call_graph_vta_fallback_site_count"] != "1" ||
		state.profile.Properties["go_call_graph_vta_fallback_reasons"] != fallback {
		t.Fatalf("VTA fallback profile outcome is incomplete: %+v", state.profile.Properties)
	}
}

func TestGoSSAInternalTestUsesRTA(t *testing.T) {
	root := ssaTestModule(t, "example.com/ssatest", map[string]string{
		"candidate.go": `package candidate

type Token struct{}
type Runner interface{ Run(Token) int }
`,
		"candidate_test.go": `package candidate

import "testing"

type TestRunner struct{}
func (TestRunner) Run(Token) int { return 1 }

func TestCandidateDispatch(t *testing.T) {
	var runner Runner = TestRunner{}
	_ = runner.Run(Token{})
}
`,
	})
	result := ssaTestScan(t, root)

	caller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssatest.TestCandidateDispatch")
	target := semanticFindNamedNode(t, result, "symbol", "method", "example.com/ssatest.(TestRunner).Run")
	site := ssaTestCandidateSite(t, result, caller.ID, "candidate_test.go", 10)
	ssaTestRequireCandidateContract(t, result, site, "rta", "interface", []string{target.ID})
	if got := goSemanticConditionValue(site.Condition, "go.package_variant"); got != "internal_test" {
		t.Fatalf("internal-test candidate condition = %q, want internal_test: %+v", got, site)
	}
	if reason, _ := site.Evidence[0].Properties["selection_reason"].(string); reason != "main_or_test_program" {
		t.Fatalf("internal-test selection reason = %q, want main_or_test_program", reason)
	}
	semanticAssertCoverageLedger(t, result)
}

func TestGoSSACallGraphLimitsAreDiagnosed(t *testing.T) {
	root := ssaTestModule(t, "example.com/ssalimits", map[string]string{
		"limits.go": `package limits

import (
	"plugin"
	_ "unsafe"
)

//go:linkname linked runtime.nanotime
func linked() int64

//export NativeCallback
func NativeCallback() {}

func UsePlugin() {
	_, _ = plugin.Open("missing.so")
}
`,
		"bridge.s": "// assembly boundary\nTEXT ·bridge(SB),$0-0\n\tRET\n",
	})
	result := ssaTestScan(t, root)

	want := map[string]string{
		"unsafe":                  "limits.go",
		"plugin":                  "limits.go",
		"go_linkname":             "limits.go",
		"assembly_declaration":    "limits.go",
		"native_callback":         "limits.go",
		"assembly_implementation": "bridge.s",
	}
	seen := map[string]int{}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code != "go_callgraph_limit" {
			continue
		}
		boundary, _ := diagnostic.Properties["boundary"].(string)
		seen[boundary]++
		if diagnostic.ID == "" || diagnostic.Severity != "warning" || !diagnostic.Recoverable {
			t.Fatalf("call graph limit lost diagnostic contract: %+v", diagnostic)
		}
		if wantPath, ok := want[boundary]; !ok || diagnostic.Path != wantPath {
			t.Fatalf("unexpected call graph limit diagnostic: %+v", diagnostic)
		}
		if len(diagnostic.Evidence) == 0 || diagnostic.StartLine == 0 || diagnostic.StartColumn == 0 {
			t.Fatalf("source-backed limit lacks evidence/span: %+v", diagnostic)
		}
		siteID, _ := diagnostic.Properties["site_id"].(string)
		site := semanticSiteByID(t, result, siteID)
		if diagnostic.ProfileID != site.ProfileID || diagnostic.Path != site.Evidence[0].Path ||
			diagnostic.StartLine != site.Evidence[0].StartLine || diagnostic.StartColumn != site.Evidence[0].StartColumn ||
			diagnostic.EndLine != site.Evidence[0].EndLine || diagnostic.EndColumn != site.Evidence[0].EndColumn ||
			!reflect.DeepEqual(diagnostic.Evidence, site.Evidence) {
			t.Fatalf("call graph diagnostic is not correlated with its site: diagnostic=%+v site=%+v", diagnostic, site)
		}
		if got, _ := site.Evidence[0].Properties["callgraph_boundary"].(string); got != boundary {
			t.Fatalf("site boundary = %q, want %q: %+v", got, boundary, site)
		}
		if reason, _ := diagnostic.Properties["reason"].(string); reason == "" || site.Reason != reason && site.ResolutionStatus == "unresolved" {
			t.Fatalf("boundary reason was not preserved: diagnostic=%+v site=%+v", diagnostic, site)
		}
	}
	for boundary := range want {
		if seen[boundary] != 1 {
			t.Fatalf("call graph limit %q count = %d, want 1; diagnostics=%+v", boundary, seen[boundary], result.Diagnostics)
		}
	}
	if result.Coverage.ProjectCodeExecuted {
		t.Fatal("limit scan reported project-code execution")
	}
	if got := result.Profile.Properties["go_callgraph_boundary_site_count"]; got != "6" {
		t.Fatalf("profile boundary site count = %q, want 6: %+v", got, result.Profile.Properties)
	}
	if !containsString(result.Coverage.Completeness, "semantic-complete") {
		t.Fatalf("explicit call graph boundaries prevented semantic completeness: %+v", result.Coverage)
	}
	for _, site := range result.Sites {
		if site.Kind != "native_callback" {
			continue
		}
		target := semanticNodeByID(t, result, site.TargetIDs[0])
		if target.Kind != "external_system" || target.Locator != "native-callback:NativeCallback" ||
			target.Properties["native_kind"] != "callback" {
			t.Fatalf("native callback identity was not normalized: site=%+v target=%+v", site, target)
		}
	}
	assemblyFileID := ""
	for _, node := range result.Nodes {
		if node.Kind == "file" && node.Locator == "file:bridge.s" {
			assemblyFileID = node.ID
		}
	}
	assemblyOwned := false
	for _, edge := range result.Edges {
		if edge.Kind == "contains" && edge.Target == assemblyFileID &&
			semanticNodeByID(t, result, edge.Source).Kind == "build_unit" {
			assemblyOwned = true
		}
	}
	if assemblyFileID == "" || !assemblyOwned {
		t.Fatalf("assembly file is not owned by its package build unit: file=%q edges=%+v", assemblyFileID, result.Edges)
	}
	var events bytes.Buffer
	if err := Emit(&events, "callgraph-boundaries", result); err != nil {
		t.Fatalf("boundary graph violates the worker protocol: %v", err)
	}
}

func TestGoReflectionBoundariesRetainDedicatedSitesWithoutInventingTargets(t *testing.T) {
	root := ssaTestModule(t, "example.com/reflectionlimits", map[string]string{
		"reflection.go": `package reflectionlimits

import "reflect"

func Boundaries(value reflect.Value, typ reflect.Type) {
	value.Call(nil)
	value.CallSlice(nil)
	_ = value.MethodByName("Run")
	_, _ = typ.MethodByName("Run")
	_ = value.FieldByName("Fn")
	_, _ = typ.FieldByName("Fn")
	_ = reflect.MakeFunc(reflect.TypeOf(func() {}), func([]reflect.Value) []reflect.Value { return nil })
}
`,
	})
	result := ssaTestScan(t, root)
	want := map[string]struct {
		count  int
		status string
		reason string
	}{
		"reflection_call":          {count: 1, status: "unresolved", reason: "reflection_call_target_boundary"},
		"reflection_call_slice":    {count: 1, status: "unresolved", reason: "reflection_call_slice_target_boundary"},
		"reflection_method_lookup": {count: 2, status: "external", reason: "reflection_method_lookup_boundary"},
		"reflection_field_lookup":  {count: 2, status: "external", reason: "reflection_field_lookup_boundary"},
		"reflection_make_func":     {count: 1, status: "external", reason: "reflection_function_construction_boundary"},
	}
	seen := map[string]int{}
	diagnosticsBySite := map[string]Diagnostic{}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == "go_callgraph_limit" {
			siteID, _ := diagnostic.Properties["site_id"].(string)
			diagnosticsBySite[siteID] = diagnostic
		}
	}
	for _, site := range result.Sites {
		if len(site.Evidence) == 0 {
			continue
		}
		boundary, _ := site.Evidence[0].Properties["callgraph_boundary"].(string)
		if !strings.HasPrefix(boundary, "reflection_") {
			continue
		}
		contract, ok := want[boundary]
		if !ok {
			t.Fatalf("unexpected reflection boundary %q: %+v", boundary, site)
		}
		seen[boundary]++
		if site.Kind != "call" || site.ResolutionStatus != contract.status ||
			site.Evidence[0].Properties["boundary_reason"] != contract.reason {
			t.Fatalf("reflection boundary lost its site contract: boundary=%s site=%+v", boundary, site)
		}
		if contract.status == "unresolved" {
			if site.Reason != contract.reason || len(site.TargetIDs) != 1 ||
				semanticNodeByID(t, result, site.TargetIDs[0]).Kind != "unknown_target" {
				t.Fatalf("runtime-only reflection call invented a target: %+v", site)
			}
		} else if site.Reason != "" || site.Precision != "exact" {
			t.Fatalf("known reflection API call lost exact external resolution: %+v", site)
		}
		diagnostic, ok := diagnosticsBySite[site.ID]
		if !ok || diagnostic.Properties["boundary"] != boundary || diagnostic.Properties["reason"] != contract.reason ||
			!reflect.DeepEqual(diagnostic.Evidence, site.Evidence) {
			t.Fatalf("reflection boundary diagnostic is not correlated: boundary=%s site=%+v diagnostic=%+v", boundary, site, diagnostic)
		}
	}
	for boundary, contract := range want {
		if seen[boundary] != contract.count {
			t.Fatalf("reflection boundary %q count = %d, want %d; sites=%+v", boundary, seen[boundary], contract.count, result.Sites)
		}
	}
	if got := result.Profile.Properties["go_callgraph_boundary_site_count"]; got != "7" {
		t.Fatalf("reflection boundary profile count = %q, want 7: %+v", got, result.Profile.Properties)
	}
	if !containsString(result.Coverage.Completeness, "semantic-complete") {
		t.Fatalf("reflection boundary ledger prevented semantic completeness: %+v", result.Coverage)
	}
	semanticAssertCoverageLedger(t, result)
}

func TestGoCallGraphBoundariesSurvivePartialSyntax(t *testing.T) {
	root := ssaTestModule(t, "example.com/partiallimits", map[string]string{
		"broken.go": `package partiallimits

import _ "unsafe"

//go:linkname linked runtime.nanotime
func linked() int64

var broken =
`,
	})
	result := ssaTestScan(t, root)
	seen := map[string]bool{}
	for _, site := range result.Sites {
		if len(site.Evidence) == 0 || site.Evidence[0].Path != "broken.go" {
			continue
		}
		boundary, _ := site.Evidence[0].Properties["callgraph_boundary"].(string)
		if boundary != "" {
			seen[boundary] = true
		}
	}
	for _, boundary := range []string{"unsafe", "go_linkname", "assembly_declaration"} {
		if !seen[boundary] {
			t.Fatalf("partial syntax lost %q boundary: sites=%+v diagnostics=%+v", boundary, result.Sites, result.Diagnostics)
		}
	}
	if containsString(result.Coverage.Completeness, "semantic-complete") ||
		!containsString(result.Coverage.Reasons, "go-packages-parser-fallback") {
		t.Fatalf("partial syntax claimed complete semantic coverage: %+v", result.Coverage)
	}
	completion := semanticFileCompletion(t, result, "broken.go")
	if !completion.Skipped || completion.SkippedSites != 1 {
		t.Fatalf("partial syntax file ledger lost its skipped item: %+v", completion)
	}
	semanticAssertCoverageLedger(t, result)
}

func TestGoSSACandidateOutputIsDeterministic(t *testing.T) {
	root := ssaTestModule(t, "example.com/ssadeterministic", map[string]string{
		"candidate/candidate.go": ssaLibrarySource,
	})
	first := ssaTestScan(t, root)
	second := ssaTestScan(t, root)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("two SSA candidate scans of the same root differ")
	}

	var firstEvents, secondEvents bytes.Buffer
	if err := Emit(&firstEvents, "ssa-determinism", first); err != nil {
		t.Fatalf("first Emit() error = %v", err)
	}
	if err := Emit(&secondEvents, "ssa-determinism", second); err != nil {
		t.Fatalf("second Emit() error = %v", err)
	}
	if !bytes.Equal(firstEvents.Bytes(), secondEvents.Bytes()) {
		t.Fatal("two SSA candidate emissions differ")
	}

	candidates := 0
	for _, site := range first.Sites {
		if site.Kind != "call" || site.ResolutionStatus != "candidates" {
			continue
		}
		candidates++
		ssaTestRequireCandidateContract(t, first, site, "cha", "", site.TargetIDs)
	}
	if candidates != 2 || first.Coverage.Candidates != candidates {
		t.Fatalf("candidate coverage = %d/sites=%d, want 2", first.Coverage.Candidates, candidates)
	}
	semanticAssertCoverageLedger(t, first)
}

func TestGoSSAGenericCandidatesPreserveCallerAndInstanceIdentity(t *testing.T) {
	mainRoot := ssaTestModule(t, "example.com/ssagenericmain", map[string]string{
		"main.go": `package main

type Token struct{}
func Target(Token) int { return 1 }

func Generic[T any](target func(Token) int, value Token) int {
	invoke := func() int {
		return target(value)
	}
	return invoke()
}

func main() {
	_ = Generic[int](Target, Token{})
}
`,
	})
	mainResult := ssaTestScan(t, mainRoot)
	target := semanticFindNamedNode(t, mainResult, "symbol", "function", "example.com/ssagenericmain.Target")
	genericSite := ssaTestCandidateSiteAt(t, mainResult, "main.go", 8)
	if semanticNodeKind(semanticNodeByID(t, mainResult, genericSite.Source)) != "closure" {
		t.Fatalf("generic closure call source is not the original closure symbol: %+v", genericSite)
	}
	ssaTestRequireCandidateContract(t, mainResult, genericSite, "rta", "function_value", []string{target.ID})

	libraryRoot := ssaTestModule(t, "example.com/ssagenericlibrary", map[string]string{
		"generic.go": `package main

func GenericTarget[T any](T) {}

func LocalInstanceCall() {
	type Local int
	target := GenericTarget[Local]
	target(Local(1))
}

func main() { LocalInstanceCall() }
`,
	})
	libraryResult := ssaTestScan(t, libraryRoot)
	caller := semanticFindNamedNode(t, libraryResult, "symbol", "function", "example.com/ssagenericlibrary.LocalInstanceCall")
	var instance Node
	for _, node := range libraryResult.Nodes {
		if node.Kind != "symbol" || semanticNodeKind(node) != "function_instance" {
			continue
		}
		identity := semanticIdentity(t, node)
		if identity["generic_origin"] == "example.com/ssagenericlibrary.GenericTarget" {
			if instance.ID != "" {
				t.Fatalf("multiple local-type GenericTarget instances: %s and %s", instance.ID, node.ID)
			}
			instance = node
		}
	}
	if instance.ID == "" {
		t.Fatal("local-type GenericTarget function instance was not emitted")
	}
	instanceSite := ssaTestCandidateSite(t, libraryResult, caller.ID, "generic.go", 8)
	ssaTestRequireCandidateContract(t, libraryResult, instanceSite, "rta", "function_value", []string{instance.ID})
}

func TestGoSSAGenericReceiverMethodCandidatesMapToOrigin(t *testing.T) {
	root := ssaTestModule(t, "example.com/ssagenericreceiver", map[string]string{
		"main.go": `package main

type Getter interface{ Get() int }
type Box[T any] struct{ Value T }
func (box Box[T]) Get() T { return box.Value }

func InterfaceCall(value Getter) int { return value.Get() }
func FunctionCall(target func() int) int { return target() }

func main() {
	box := Box[int]{Value: 1}
	_ = InterfaceCall(box)
	_ = FunctionCall(box.Get)
}
`,
	})
	result := ssaTestScan(t, root)
	target := semanticFindNamedNode(t, result, "symbol", "method", "example.com/ssagenericreceiver.(Box).Get")

	interfaceCaller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssagenericreceiver.InterfaceCall")
	interfaceSite := ssaTestCandidateSite(t, result, interfaceCaller.ID, "main.go", 7)
	ssaTestRequireCandidateContract(t, result, interfaceSite, "rta", "interface", []string{target.ID})

	functionCaller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssagenericreceiver.FunctionCall")
	functionSite := ssaTestCandidateSite(t, result, functionCaller.ID, "main.go", 8)
	ssaTestRequireCandidateContract(t, result, functionSite, "rta", "function_value", []string{target.ID})
}

func TestGoSSANormalAndExternalVariantsExcludeIncompatibleTestTargets(t *testing.T) {
	normalRoot := ssaTestModule(t, "example.com/ssanormalvariant", map[string]string{
		"candidate.go": `package candidate

type Token struct{}
type Runner interface{ Run(Token) int }
type Normal struct{}
func (Normal) Run(Token) int { return 1 }

func Call(r Runner, value Token) int {
	return r.Run(value)
}
`,
		"candidate_test.go": `package candidate

type TestOnly struct{}
func (TestOnly) Run(Token) int { return 2 }
`,
	})
	normalResult := ssaTestScan(t, normalRoot)
	caller := semanticFindNamedNode(t, normalResult, "symbol", "function", "example.com/ssanormalvariant.Call")
	normal := semanticFindNamedNode(t, normalResult, "symbol", "method", "example.com/ssanormalvariant.(Normal).Run")
	testOnly := semanticFindNamedNode(t, normalResult, "symbol", "method", "example.com/ssanormalvariant.(TestOnly).Run")
	normalSite := ssaTestCandidateSite(t, normalResult, caller.ID, "candidate.go", 9)
	ssaTestRequireCandidateContract(t, normalResult, normalSite, "cha", "interface", []string{normal.ID})
	if containsString(normalSite.TargetIDs, testOnly.ID) {
		t.Fatalf("normal candidate leaked a _test.go-only target: %+v", normalSite)
	}

	variantRoot := ssaTestModule(t, "example.com/ssavariants", map[string]string{
		"candidate.go": `package candidate

type Token struct{}
type Runner interface{ Run(Token) int }
`,
		"candidate_test.go": `package candidate

import "testing"

type Internal struct{}
func (Internal) Run(Token) int { return 1 }

func TestInternal(t *testing.T) {
	var runner Runner = Internal{}
	_ = runner.Run(Token{})
}
`,
		"external_test.go": `package candidate_test

import (
	"testing"
	candidate "example.com/ssavariants"
)

type External struct{}
func (External) Run(candidate.Token) int { return 2 }

func TestExternal(t *testing.T) {
	var runner candidate.Runner = External{}
	_ = runner.Run(candidate.Token{})
}
`,
	})
	variantResult := ssaTestScan(t, variantRoot)
	internalCaller := semanticFindNamedNode(t, variantResult, "symbol", "function", "example.com/ssavariants.TestInternal")
	internalTarget := semanticFindNamedNode(t, variantResult, "symbol", "method", "example.com/ssavariants.(Internal).Run")
	externalCaller := semanticFindNamedNode(t, variantResult, "symbol", "function", "example.com/ssavariants_test.TestExternal")
	externalTarget := semanticFindNamedNode(t, variantResult, "symbol", "method", "example.com/ssavariants_test.(External).Run")
	internalSite := ssaTestCandidateSite(t, variantResult, internalCaller.ID, "candidate_test.go", 10)
	externalSite := ssaTestCandidateSite(t, variantResult, externalCaller.ID, "external_test.go", 13)
	ssaTestRequireCandidateContract(t, variantResult, internalSite, "rta", "interface", []string{internalTarget.ID})
	ssaTestRequireCandidateContract(t, variantResult, externalSite, "rta", "interface", []string{externalTarget.ID})
}

func TestGoSSACandidateResolvesAcrossWorkspaceModules(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.26.1\n\nuse (\n\t./app\n\t./lib\n)\n")
	writeTestFile(t, filepath.Join(root, "lib", "go.mod"), "module example.com/ssa-lib\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "lib", "lib.go"), `package lib

type Token struct{}
type Impl struct{}
func (Impl) Run(Token) int { return 1 }
`)
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), "module example.com/ssa-app\n\ngo 1.26.1\n\nrequire example.com/ssa-lib v0.0.0\n")
	writeTestFile(t, filepath.Join(root, "app", "app.go"), `package app

import lib "example.com/ssa-lib"

type Runner interface{ Run(lib.Token) int }
func Call(r Runner, value lib.Token) int { return r.Run(value) }
`)

	result := ssaTestScan(t, root)
	caller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssa-app.Call")
	target := semanticFindNamedNode(t, result, "symbol", "method", "example.com/ssa-lib.(Impl).Run")
	site := ssaTestCandidateSite(t, result, caller.ID, "app/app.go", 6)
	ssaTestRequireCandidateContract(t, result, site, "cha", "interface", []string{target.ID})
}

func TestGoSSACandidatesResolveAcrossLocalReplacement(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "lib", "go.mod"), "module example.com/ssa-new\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "lib", "lib.go"), `package lib

func Generic[T any](value T) T { return value }
var Handler = func(value, increment int) int { return value + increment }
`)
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), `module example.com/ssa-replace-app

go 1.26.1

require example.com/ssa-old v0.0.0
replace example.com/ssa-old => ../lib
`)
	writeTestFile(t, filepath.Join(root, "app", "app.go"), `package app

import old "example.com/ssa-old"

type Token struct{}

func Call(value Token) Token {
	target := old.Generic[Token]
	return target(value)
}

func ClosureCall(value int) int {
	target := old.Handler
	return target(value, 1)
}
`)

	result := ssaTestScan(t, root)
	caller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssa-replace-app.Call")
	var instance Node
	for _, node := range result.Nodes {
		if node.Kind != "symbol" || semanticNodeKind(node) != "function_instance" {
			continue
		}
		identity := semanticIdentity(t, node)
		if identity["generic_origin"] == "example.com/ssa-new.Generic" {
			instance = node
		}
	}
	if instance.ID == "" {
		t.Fatal("replacement-backed generic function instance was not emitted")
	}
	site := ssaTestCandidateSite(t, result, caller.ID, "app/app.go", 9)
	ssaTestRequireCandidateContract(t, result, site, "cha", "function_value", []string{instance.ID})

	closureCaller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/ssa-replace-app.ClosureCall")
	var closure Node
	for _, node := range result.Nodes {
		if node.Kind != "symbol" || semanticNodeKind(node) != "closure" {
			continue
		}
		identity := semanticIdentity(t, node)
		if identity["relative_path"] == "lib/lib.go" {
			if closure.ID != "" {
				t.Fatalf("multiple replacement-backed closures: %s and %s", closure.ID, node.ID)
			}
			closure = node
		}
	}
	if closure.ID == "" {
		t.Fatal("replacement-backed closure was not emitted")
	}
	closureSite := ssaTestCandidateSite(t, result, closureCaller.ID, "app/app.go", 14)
	ssaTestRequireCandidateContract(t, result, closureSite, "cha", "function_value", []string{closure.ID})
}

func TestGoSSAInputCompletenessRejectsPartialDependencySyntax(t *testing.T) {
	pkg := &packages.Package{
		ID:              "example.com/partial",
		PkgPath:         "example.com/partial",
		CompiledGoFiles: []string{"one.go", "two.go"},
		Syntax:          []*ast.File{{Name: ast.NewIdent("partial")}},
		Fset:            token.NewFileSet(),
		Types:           types.NewPackage("example.com/partial", "partial"),
		TypesInfo:       &types.Info{},
		TypesSizes:      types.SizesFor("gc", "amd64"),
	}
	if complete, reason := goSSAInputCompleteness([]*packages.Package{pkg}); complete || reason == "" {
		t.Fatalf("partial dependency syntax completeness = %t, reason=%q", complete, reason)
	}
	pkg.CompiledGoFiles = []string{"one.go"}
	pkg.Syntax = []*ast.File{nil}
	if complete, reason := goSSAInputCompleteness([]*packages.Package{pkg}); complete || reason == "" {
		t.Fatalf("nil dependency syntax completeness = %t, reason=%q", complete, reason)
	}
}

func ssaTestModule(t *testing.T, modulePath string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module "+modulePath+"\n\ngo 1.26.1\n")
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		writeTestFile(t, filepath.Join(root, filepath.FromSlash(path)), files[path])
	}
	return root
}

func ssaTestScan(t *testing.T, root string) Result {
	t.Helper()
	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if got := result.Profile.Properties["go_ssa_builder_mode"]; got != "instantiate-generics,serial" {
		t.Fatalf("SSA builder mode = %q, want instantiate-generics,serial", got)
	}
	if got := result.Profile.Properties["go_call_graph_vta_engine"]; got != goVTACallGraphEngine {
		t.Fatalf("VTA engine = %q, want %q", got, goVTACallGraphEngine)
	}
	return result
}

func ssaTestCandidateSite(t *testing.T, result Result, sourceID, path string, line int) Site {
	t.Helper()
	var matches []Site
	for _, site := range result.Sites {
		if site.Kind == "call" && site.ResolutionStatus == "candidates" && site.Source == sourceID &&
			len(site.Evidence) > 0 && site.Evidence[0].Path == path && site.Evidence[0].StartLine == line {
			matches = append(matches, site)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("candidate call %s:%d from %s matches = %d, want 1; sites=%+v diagnostics=%+v", path, line, sourceID, len(matches), result.Sites, result.Diagnostics)
	}
	return matches[0]
}

func ssaTestCandidateSiteAt(t *testing.T, result Result, path string, line int) Site {
	t.Helper()
	var matches []Site
	for _, site := range result.Sites {
		if site.Kind == "call" && site.ResolutionStatus == "candidates" && len(site.Evidence) > 0 &&
			site.Evidence[0].Path == path && site.Evidence[0].StartLine == line {
			matches = append(matches, site)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("candidate call %s:%d matches = %d, want 1; sites=%+v", path, line, len(matches), result.Sites)
	}
	return matches[0]
}

func ssaTestRequireCandidateContract(t *testing.T, result Result, site Site, algorithm, dispatch string, wantTargets []string) {
	t.Helper()
	nodes := make(map[string]Node, len(result.Nodes))
	for _, node := range result.Nodes {
		nodes[node.ID] = node
	}
	wantTargets = append([]string(nil), wantTargets...)
	sort.Strings(wantTargets)
	if !reflect.DeepEqual(site.TargetIDs, wantTargets) {
		t.Fatalf("candidate targets = %v, want %v: %+v", site.TargetIDs, wantTargets, site)
	}
	if site.Kind != "call" || site.ResolutionStatus != "candidates" || site.Precision != "overapprox" || site.Reason != "" {
		t.Fatalf("invalid candidate site classification: %+v", site)
	}
	if nodes[site.Source].Kind != "symbol" || len(site.TargetIDs) == 0 || !sort.StringsAreSorted(site.TargetIDs) {
		t.Fatalf("candidate source/target set is invalid: site=%+v source=%+v", site, nodes[site.Source])
	}
	for index, targetID := range site.TargetIDs {
		if nodes[targetID].Kind != "symbol" {
			t.Fatalf("candidate target is not a symbol: site=%+v target=%+v", site, nodes[targetID])
		}
		if index > 0 && site.TargetIDs[index-1] == targetID {
			t.Fatalf("candidate targets are not unique: %+v", site)
		}
	}
	if len(site.Evidence) == 0 {
		t.Fatalf("candidate site has no evidence: %+v", site)
	}
	primary := site.Evidence[0]
	if primary.Kind != "semantic" || primary.Extractor != "go-ssa" || primary.ExtractorVersion != AdapterVersion {
		t.Fatalf("candidate site has invalid SSA evidence: %+v", primary)
	}
	if got, _ := primary.Properties["algorithm"].(string); got != algorithm {
		t.Fatalf("candidate algorithm = %q, want %q: %+v", got, algorithm, primary)
	}
	if dispatch != "" {
		if got, _ := primary.Properties["dispatch"].(string); got != dispatch {
			t.Fatalf("candidate dispatch = %q, want %q: %+v", got, dispatch, primary)
		}
	}
	wantScope := map[string]string{"rta": "complete_program", "cha": "partial_program"}[algorithm]
	if algorithm == "vta" {
		wantScope = "complete_program"
	}
	if got, _ := primary.Properties["analysis_scope"].(string); got != wantScope {
		t.Fatalf("candidate analysis scope = %q, want %q: %+v", got, wantScope, primary)
	}
	if got, ok := primary.Properties["candidate_count"].(int); !ok || got != len(site.TargetIDs) {
		t.Fatalf("candidate evidence count = %v, want %d: %+v", primary.Properties["candidate_count"], len(site.TargetIDs), primary)
	}
	wantRequested, wantFallback := "rta-cha", "not_requested"
	if result.Profile.Properties["go_call_graph_requested"] == "vta" {
		wantRequested = "vta"
		wantFallback = "none"
	}
	if got, _ := primary.Properties["requested_algorithm"].(string); got != wantRequested {
		t.Fatalf("candidate requested algorithm = %q, want %q: %+v", got, wantRequested, primary)
	}
	if got, _ := primary.Properties["fallback_reason"].(string); got != wantFallback {
		t.Fatalf("candidate fallback reason = %q, want %q: %+v", got, wantFallback, primary)
	}
	wantSiteID := semanticCanonicalValueID("site", map[string]any{
		"condition": site.Condition, "kind": "call", "path": primary.Path,
		"profile_id": site.ProfileID, "source": site.Source,
		"span": map[string]any{
			"start_line": primary.StartLine, "start_column": primary.StartColumn,
			"end_line": primary.EndLine, "end_column": primary.EndColumn,
		},
	})
	if site.ID != wantSiteID {
		t.Fatalf("candidate site ID = %q, want %q", site.ID, wantSiteID)
	}

	edges := map[string]Edge{}
	for _, edge := range result.Edges {
		if edge.SiteID != site.ID {
			continue
		}
		if edge.Kind != "may_call" {
			t.Fatalf("candidate site retained non-may_call edge: %+v", edge)
		}
		if _, duplicate := edges[edge.Target]; duplicate {
			t.Fatalf("candidate site has duplicate edge target: %+v", edge)
		}
		edges[edge.Target] = edge
	}
	if len(edges) != len(site.TargetIDs) {
		t.Fatalf("candidate edge count = %d, want %d: %+v", len(edges), len(site.TargetIDs), site)
	}
	for _, targetID := range site.TargetIDs {
		edge, ok := edges[targetID]
		if !ok {
			t.Fatalf("candidate site lacks may_call edge to %s", targetID)
		}
		if edge.Source != site.Source || edge.ResolutionStatus != "candidates" || edge.Precision != "overapprox" ||
			edge.Phase != "semantic" || edge.Environment != "any" || edge.ProfileID != site.ProfileID ||
			!reflect.DeepEqual(edge.Condition, site.Condition) || !reflect.DeepEqual(edge.Evidence[0], primary) {
			t.Fatalf("candidate edge disagrees with site: edge=%+v site=%+v", edge, site)
		}
		wantEdgeID := semanticCanonicalValueID("edge", map[string]any{
			"kind": "may_call", "site_id": site.ID, "target": targetID,
		})
		if edge.ID != wantEdgeID {
			t.Fatalf("candidate edge ID = %q, want %q", edge.ID, wantEdgeID)
		}
	}
}
