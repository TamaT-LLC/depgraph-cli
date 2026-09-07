package worker

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestAnalysisUnitCapabilitiesAdvertiseThePackageLoader(t *testing.T) {
	want := []string{
		AnalysisGoPackageLoaderCapability,
		AnalysisLoaderScopeCapability,
		AnalysisUnitCapability,
		AnalysisUnitTypedCapability,
	}
	if !reflect.DeepEqual(AnalysisUnitCapabilities, want) {
		t.Fatalf("AnalysisUnitCapabilities = %v, want %v", AnalysisUnitCapabilities, want)
	}
	// The core handshake parser rejects the whole list unless it is strictly
	// ascending, which would silently demote every scan to the repository
	// worker.
	if !sort.StringsAreSorted(AnalysisUnitCapabilities) {
		t.Fatalf("AnalysisUnitCapabilities = %v are not sorted", AnalysisUnitCapabilities)
	}
	for index := 1; index < len(AnalysisUnitCapabilities); index++ {
		if AnalysisUnitCapabilities[index-1] == AnalysisUnitCapabilities[index] {
			t.Fatalf("AnalysisUnitCapabilities repeat %q", AnalysisUnitCapabilities[index])
		}
	}
}

func splitTestPackageBinding(kind, splitKind string, paths, roots, references []string) *AnalysisSplitBinding {
	return &AnalysisSplitBinding{
		ContractVersion: AnalysisSplitContractVersion,
		SplitPlanID:     "analysis-split-plan:scan",
		ExecutionUnitID: "analysis-execution-unit:" + splitKind + ":" + strings.Join(paths, ","),
		SplitKind:       splitKind,
		Loader: AnalysisLoaderBinding{
			Kind: kind, Paths: paths, PackageRoots: roots, ReferenceDepth: "declarations",
			ReferencePaths: references, InputSplit: len(references) > 0,
		},
	}
}

// TestPackageLoaderBindingRelaxesTypedChunking: only a package-bound typed
// request may own a subset of the module it receives as context; unbound and
// module-bound typed requests keep the single-chunk rule of the v2 contract.
func TestPackageLoaderBindingRelaxesTypedChunking(t *testing.T) {
	request := goLoaderCallGraphRequest()
	request.Stage = AnalysisUnitStageTyped
	request.ChunkIndex, request.ChunkCount = 0, 2
	request.Split = splitTestPackageBinding("package", "output_batch",
		[]string{"use/use.go", "use/use_external_test.go"}, []string{"use"}, []string{"cmd/app/main.go", "shape/shape.go"})
	if err := request.Validate(); err != nil {
		t.Fatalf("package-bound typed chunk was rejected: %v", err)
	}
	options := request.scanOptions("")
	if options.loaderMode != goLoaderModePackage || len(options.loaderTargets) != 1 || options.loaderTargets[0].Dir != "use" {
		t.Fatalf("scanOptions = %+v", options)
	}
	// The package-bound typed stage is the declaration stage: every body of
	// the target package is stripped, so the typed checkpoint never holds
	// types and bodies together and the semantic units own every body.
	if options.bodyPaths == nil || len(options.bodyPaths) != 0 {
		t.Fatalf("typed declaration stage bodyPaths = %v, want an empty set", options.bodyPaths)
	}
	semanticWhole := request
	semanticWhole.Stage = AnalysisUnitStageSemantic
	semanticWhole.ChunkIndex, semanticWhole.ChunkCount = 0, 1
	semanticWhole.Split.SplitKind = "whole"
	if options := semanticWhole.scanOptions(""); options.bodyPaths != nil {
		t.Fatalf("whole package-bound semantic chunk staged bodies: %+v", options)
	}

	unbound := request
	unbound.Split = nil
	if err := unbound.Validate(); err == nil || !strings.Contains(err.Error(), "exactly one chunk") {
		t.Fatalf("unbound typed chunk error = %v, want the single-chunk rule", err)
	}
	moduleBound := request
	moduleBound.Split = splitTestPackageBinding("module", "output_batch",
		request.ContextPaths, []string{".", "cmd/app", "shape", "use"}, nil)
	moduleBound.Split.Loader.ReferenceDepth = "bodies"
	if err := moduleBound.Validate(); err == nil || !strings.Contains(err.Error(), "exactly one chunk") {
		t.Fatalf("module-bound typed chunk error = %v, want the single-chunk rule", err)
	}
	if options := moduleBound.scanOptions("/cache"); options.loaderMode != "" || options.buildCacheDir != "/cache" {
		t.Fatalf("module binding selected the package loader: %+v", options)
	}
	syntax := request
	syntax.Stage = AnalysisUnitStageSyntax
	syntax.Split.Loader.Kind = "files"
	syntax.Split.Loader.ReferenceDepth = "paths_only"
	if options := syntax.scanOptions(""); options.loaderMode != "" {
		t.Fatalf("syntax request selected a typed loader: %+v", options)
	}
}

// TestStagedBodiesChunksPartitionThePackageSemanticGraph runs the semantic
// stage of one package as two staged-bodies chunks and as one whole
// package-bound chunk. Each chunk type-checks the bodies of its own files only,
// the other file of the package contributes declarations, and the union of the
// chunks is exactly the whole chunk's site and edge graph.
func TestStagedBodiesChunksPartitionThePackageSemanticGraph(t *testing.T) {
	root := goLoaderCallGraphFixture(t)
	base := goLoaderCallGraphRequest()
	references := []string{"cmd/app/main.go", "shape/shape.go"}
	whole := base
	whole.Split = splitTestPackageBinding("package", "whole", base.SourcePaths, []string{"use"}, references)
	chunk := func(index int, owned string, other string) AnalysisUnitRequest {
		request := base
		request.SourcePaths = []string{owned}
		request.ChunkID = fmt.Sprintf("staged-%d", index)
		request.ChunkIndex, request.ChunkCount = index, 2
		request.Split = splitTestPackageBinding("package", "staged_bodies", []string{owned}, []string{"use"}, append(append([]string(nil), references...), other))
		sort.Strings(request.Split.Loader.ReferencePaths)
		return request
	}
	first := chunk(0, "use/use.go", "use/use_external_test.go")
	second := chunk(1, "use/use_external_test.go", "use/use.go")
	for _, request := range []AnalysisUnitRequest{whole, first, second} {
		if err := request.Validate(); err != nil {
			t.Fatalf("request %s: %v", request.ChunkID, err)
		}
	}
	options := first.scanOptions("")
	if !options.bodyPaths["use/use.go"] || len(options.bodyPaths) != 1 {
		t.Fatalf("staged bodies scanOptions = %+v", options)
	}

	run := func(request AnalysisUnitRequest) Result {
		result, err := ScanWithAnalysisUnit(root, "", request)
		if err != nil {
			t.Fatalf("%s: %v", request.ChunkID, err)
		}
		if result.Profile.Properties["go_packages_status"] != "loaded" {
			t.Skipf("constrained Go environment unavailable: %s", goLoaderDiagnosticSummary(result.Diagnostics))
		}
		if !containsString(result.Coverage.Completeness, "semantic-complete") || containsString(result.Coverage.Reasons, "go-semantic-incomplete") {
			t.Fatalf("%s coverage = %+v, diagnostics = %s", request.ChunkID, result.Coverage, goLoaderDiagnosticSummary(result.Diagnostics))
		}
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.Code == "go_loader_target_incomplete" {
				t.Fatalf("%s reported a type error after staging bodies: %s", request.ChunkID, diagnostic.Message)
			}
		}
		return result
	}
	wholeResult := run(whole)
	firstResult := run(first)
	secondResult := run(second)

	for _, entry := range []struct {
		name   string
		result Result
		want   map[string]string
	}{
		{"whole", wholeResult, map[string]string{
			"analysis_split_kind": "whole", "go_loader_body_files": "2", "go_loader_declaration_only_files": "0",
		}},
		{"first", firstResult, map[string]string{
			"analysis_split_kind": "staged_bodies", "go_loader_body_files": "1", "go_loader_declaration_only_files": "1",
		}},
		{"second", secondResult, map[string]string{
			"analysis_split_kind": "staged_bodies", "go_loader_body_files": "1", "go_loader_declaration_only_files": "1",
		}},
	} {
		want := map[string]string{
			"analysis_loader_scope":               AnalysisLoaderScopeApplied,
			"analysis_loader_mode":                "package",
			"analysis_loader_kind":                "package",
			"analysis_scope":                      "target_packages",
			"go_loader_target_packages":           "2",
			"go_loader_target_files":              "2",
			"go_loader_syntax_equals_targets":     "true",
			"go_call_graph_program_scope":         "package-with-declaration-deps",
			"go_loader_reference_packages_source": "0",
			"go_typed_stage_complete":             "true",
		}
		for key, value := range entry.want {
			want[key] = value
		}
		for key, value := range want {
			if got := entry.result.Profile.Properties[key]; got != value {
				t.Fatalf("%s profile property %s = %q, want %q", entry.name, key, got, value)
			}
		}
		for _, key := range []string{"analysis_logical_profile_id", "analysis_base_profile_id", "go_dependency_snapshot_fingerprint", "go_reference_fingerprint"} {
			if got := entry.result.Profile.Properties[key]; got == "" || got != wholeResult.Profile.Properties[key] {
				t.Fatalf("%s %s = %q, whole = %q", entry.name, key, got, wholeResult.Profile.Properties[key])
			}
		}
	}

	// Sites: disjoint per chunk, and their union is the whole graph.
	union := map[string]Site{}
	for _, result := range []Result{firstResult, secondResult} {
		for _, site := range result.Sites {
			if _, duplicate := union[site.ID]; duplicate {
				t.Fatalf("site %s was emitted by both staged chunks", site.ID)
			}
			if len(site.Evidence) == 0 || site.Evidence[0].Path != result.Profile.Properties["analysis_unit_id"] && !containsString(sitesOwnedPaths(result), site.Evidence[0].Path) {
				t.Fatalf("chunk %s emitted a site outside its owned files: %+v", result.Profile.Properties["analysis_chunk_id"], site)
			}
			union[site.ID] = site
		}
	}
	wholeSites := goLoaderSitesByID(wholeResult)
	if len(union) != len(wholeSites) || len(firstResult.Sites) == 0 || len(secondResult.Sites) == 0 {
		t.Fatalf("site counts: first=%d second=%d union=%d whole=%d", len(firstResult.Sites), len(secondResult.Sites), len(union), len(wholeSites))
	}
	for id, site := range union {
		counterpart, ok := wholeSites[id]
		if !ok || goLoaderSiteSummary(site) != goLoaderSiteSummary(counterpart) {
			t.Fatalf("site %s differs between staged and whole chunks:\n staged=%s\n whole =%s", id, goLoaderSiteSummary(site), goLoaderSiteSummary(counterpart))
		}
	}
	// Edges: the semantic edges of the chunks partition the whole chunk's
	// semantic edges; structural edges may repeat because every chunk emits
	// the containment of its own files.
	edgeKeys := func(result Result, phase string) []string {
		keys := make([]string, 0, len(result.Edges))
		for _, edge := range result.Edges {
			if edge.Phase != phase {
				continue
			}
			keys = append(keys, fmt.Sprintf("%s|%s|%s|%s|%s|%s", edge.Kind, edge.Phase, edge.Source, edge.Target, edge.ResolutionStatus, edge.Precision))
		}
		sort.Strings(keys)
		return keys
	}
	staged := append(edgeKeys(firstResult, "semantic"), edgeKeys(secondResult, "semantic")...)
	sort.Strings(staged)
	if wholeEdges := edgeKeys(wholeResult, "semantic"); !reflect.DeepEqual(staged, wholeEdges) {
		t.Fatalf("semantic edges differ:\n staged=%s\n whole =%s", strings.Join(staged, "\n        "), strings.Join(wholeEdges, "\n        "))
	}
	for index, keys := range [][]string{edgeKeys(firstResult, "semantic"), edgeKeys(secondResult, "semantic")} {
		if len(keys) == 0 {
			t.Fatalf("staged chunk %d emitted no semantic edges", index)
		}
	}
	// Nodes: each staged node exists in the whole chunk with the same identity.
	wholeNodes := goLoaderNodesByID(wholeResult)
	for _, result := range []Result{firstResult, secondResult} {
		for _, node := range result.Nodes {
			counterpart, ok := wholeNodes[node.ID]
			if !ok || counterpart.Kind != node.Kind || counterpart.Locator != node.Locator {
				t.Fatalf("staged node %+v is missing from the whole chunk", node)
			}
		}
	}
	// The file ledger of each chunk names its owned files only.
	for _, result := range []Result{firstResult, secondResult} {
		owned := sitesOwnedPaths(result)
		for _, completion := range result.Files {
			if strings.HasSuffix(completion.Path, ".go") && !containsString(owned, completion.Path) {
				t.Fatalf("chunk %s ledger names %s outside its owned files", result.Profile.Properties["analysis_chunk_id"], completion.Path)
			}
		}
	}
	semanticAssertCoverageLedger(t, firstResult)
	semanticAssertCoverageLedger(t, secondResult)
}

func sitesOwnedPaths(result Result) []string {
	paths := make([]string, 0)
	for _, completion := range result.Files {
		if strings.HasSuffix(completion.Path, ".go") {
			paths = append(paths, completion.Path)
		}
	}
	return paths
}

// TestPackageLoaderBindingReportsWidenedOnSourceFallback: a test-induced
// recompilation ("q [p.test]") cannot come from export data, so the loader
// reads q's declarations from source and reports that the bound was widened.
func TestPackageLoaderBindingReportsWidenedOnSourceFallback(t *testing.T) {
	root := goLoaderTestCycleFixture(t)
	owned := []string{"p/p_external_test.go", "p/p.go", "p/p_internal_test.go"}
	sort.Strings(owned)
	request := AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:cycle",
		Adapter:            AdapterName,
		UnitRoot:           ".",
		SourcePaths:        owned,
		Stage:              AnalysisUnitStageTyped,
		ContextPaths:       append(append([]string(nil), owned...), "q/q.go"),
		ChunkID:            "p",
		ChunkIndex:         0,
		ChunkCount:         2,
		ContextFingerprint: "cycle-context",
		Split:              splitTestPackageBinding("package", "output_batch", owned, []string{"p"}, []string{"q/q.go"}),
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	result, err := ScanWithAnalysisUnit(root, "", request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Properties["go_packages_status"] != "loaded" {
		t.Skipf("constrained Go environment unavailable: %s", goLoaderDiagnosticSummary(result.Diagnostics))
	}
	for key, want := range map[string]string{
		"analysis_loader_scope":               AnalysisLoaderScopeWidened,
		"analysis_loader_mode":                "package",
		"go_loader_reference_packages_source": "1",
		"go_loader_syntax_equals_targets":     "true",
		"go_typed_stage_complete":             "true",
	} {
		if got := result.Profile.Properties[key]; got != want {
			t.Fatalf("profile property %s = %q, want %q", key, got, want)
		}
	}
}
