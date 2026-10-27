package worker

import (
	"encoding/json"
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
	// An output batch of a small package keeps every body of the target
	// package; only a staged-bodies chunk restricts the bodies to the files it
	// owns, and it does so in the typed stage exactly as in the semantic one,
	// because both streams carry the body-derived references of those files.
	if options.bodyPaths != nil {
		t.Fatalf("typed output batch staged bodies: %v, want every body", options.bodyPaths)
	}
	typedStaged := request
	typedStaged.SourcePaths = []string{"use/use.go"}
	typedStaged.Split = splitTestPackageBinding("package", "staged_bodies",
		[]string{"use/use.go"}, []string{"use"}, []string{"cmd/app/main.go", "shape/shape.go", "use/use_external_test.go"})
	if err := typedStaged.Validate(); err != nil {
		t.Fatalf("package-bound staged typed chunk was rejected: %v", err)
	}
	if options := typedStaged.scanOptions(""); !options.bodyPaths["use/use.go"] || len(options.bodyPaths) != 1 {
		t.Fatalf("typed staged-bodies chunk bodyPaths = %v, want the owned file only", options.bodyPaths)
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

// stagedNodeFixture is one package of three files: a.go and b.go call each
// other across files, a.go declares a method on a type of c.go, b.go carries
// a declaration nobody references, and c.go has no function bodies at all.
func stagedNodeFixture(t *testing.T) string {
	t.Helper()
	return goLoaderTestFixture(t, map[string]string{
		"go.mod": "module example.com/staged\n\ngo 1.26.1\n",
		"p/a.go": `package p

type A struct{ N int }

func FA(n int) int { return FB(n) + 1 }

func (t T) Method() int { return int(t) + Limit }
`,
		"p/b.go": `package p

type Unused struct{ Flag bool }

func FB(n int) int {
	if n <= 0 {
		return 0
	}
	return FA(n - 1)
}

func Lonely() string { return "lonely" }
`,
		"p/c.go": `package p

type T int

const Limit = 3

var Shared = A{N: Limit}
`,
	})
}

// TestStagedBodiesChunksEmitOwnedAndEndpointNodesOnly runs the typed and the
// semantic stage of one package as three staged-bodies chunks and as one
// whole package-bound chunk. Each chunk emits the declaration nodes of the
// files it owns plus the nodes its own sites and edges name, never the rest of
// the package; every node is still emitted by at least one chunk, a node that
// several chunks emit is serialized identically, and the union of the chunks
// is the whole chunk's node, edge and site graph.
func TestStagedBodiesChunksEmitOwnedAndEndpointNodesOnly(t *testing.T) {
	root := stagedNodeFixture(t)
	files := []string{"p/a.go", "p/b.go", "p/c.go"}
	for _, stage := range []AnalysisUnitStage{AnalysisUnitStageTyped, AnalysisUnitStageSemantic} {
		t.Run(string(stage), func(t *testing.T) {
			base := AnalysisUnitRequest{
				ContractVersion:    AnalysisUnitContractVersion,
				UnitID:             "analysis-unit:staged",
				Adapter:            AdapterName,
				UnitRoot:           ".",
				SourcePaths:        files,
				Stage:              stage,
				ContextPaths:       files,
				ChunkID:            "whole",
				ChunkCount:         1,
				ContextFingerprint: "staged-context",
			}
			whole := base
			whole.Split = splitTestPackageBinding("package", "whole", files, []string{"p"}, nil)
			run := func(request AnalysisUnitRequest) Result {
				t.Helper()
				if err := request.Validate(); err != nil {
					t.Fatalf("request %s: %v", request.ChunkID, err)
				}
				result, err := ScanWithAnalysisUnit(root, "", request)
				if err != nil {
					t.Fatalf("%s: %v", request.ChunkID, err)
				}
				if result.Profile.Properties["go_packages_status"] != "loaded" {
					t.Skipf("constrained Go environment unavailable: %s", goLoaderDiagnosticSummary(result.Diagnostics))
				}
				if result.Profile.Properties["go_typed_stage_complete"] != "true" {
					t.Fatalf("%s typed stage incomplete: %s", request.ChunkID, goLoaderDiagnosticSummary(result.Diagnostics))
				}
				return result
			}
			wholeResult := run(whole)
			chunks := make([]Result, 0, len(files))
			for index, owned := range files {
				request := base
				request.SourcePaths = []string{owned}
				request.ChunkID = fmt.Sprintf("staged-%d", index)
				request.ChunkIndex, request.ChunkCount = index, len(files)
				references := make([]string, 0, len(files)-1)
				for _, other := range files {
					if other != owned {
						references = append(references, other)
					}
				}
				request.Split = splitTestPackageBinding("package", "staged_bodies", []string{owned}, []string{"p"}, references)
				chunks = append(chunks, run(request))
			}

			wholeNodes := map[string]string{}
			for _, node := range wholeResult.Nodes {
				wholeNodes[node.ID] = stagedNodeJSON(t, node)
			}
			union := map[string]string{}
			for index, result := range chunks {
				owned := files[index]
				endpoints := stagedEndpointIDs(result)
				nodes := map[string]bool{}
				for _, node := range result.Nodes {
					nodes[node.ID] = true
					encoded := stagedNodeJSON(t, node)
					if previous, ok := union[node.ID]; ok && previous != encoded {
						t.Fatalf("node %s differs between chunks:\n %s\n %s", node.ID, previous, encoded)
					}
					union[node.ID] = encoded
					if node.Kind != "symbol" && node.Kind != "type" {
						continue
					}
					sourcePath, _ := node.Properties["source_path"].(string)
					if sourcePath != owned && !endpoints[node.ID] {
						t.Fatalf("chunk %s emitted %s %s declared in %s that none of its sites or edges names", owned, node.Kind, node.DisplayName, sourcePath)
					}
				}
				for id := range endpoints {
					if !nodes[id] {
						t.Fatalf("chunk %s references node %s without declaring it", owned, id)
					}
				}
				if len(result.Nodes) >= len(wholeResult.Nodes) {
					t.Fatalf("chunk %s emitted %d nodes, whole emitted %d: the package declarations were not pruned", owned, len(result.Nodes), len(wholeResult.Nodes))
				}
			}
			if !reflect.DeepEqual(union, wholeNodes) {
				for id, encoded := range wholeNodes {
					if union[id] != encoded {
						t.Errorf("whole node missing or different in the chunk union: %s", encoded)
					}
				}
				for id, encoded := range union {
					if _, ok := wholeNodes[id]; !ok {
						t.Errorf("chunk union node absent from the whole chunk: %s", encoded)
					}
				}
				t.FailNow()
			}
			// The declarations nobody references are emitted once, by the
			// chunk that owns their file.
			for _, name := range []string{"Unused", "Lonely"} {
				emitted := 0
				for _, result := range chunks {
					for _, node := range result.Nodes {
						if node.DisplayName == name && (node.Kind == "symbol" || node.Kind == "type") {
							emitted++
						}
					}
				}
				if emitted != 1 {
					t.Fatalf("%s was emitted by %d chunks, want only its owner", name, emitted)
				}
			}

			edgeKeys := func(result Result) map[string]bool {
				keys := map[string]bool{}
				for _, edge := range result.Edges {
					edge.ProfileID = ""
					encoded, err := json.Marshal(edge)
					if err != nil {
						t.Fatal(err)
					}
					keys[string(encoded)] = true
				}
				return keys
			}
			unionEdges := map[string]bool{}
			unionSites := map[string]string{}
			for _, result := range chunks {
				for key := range edgeKeys(result) {
					unionEdges[key] = true
				}
				for _, site := range result.Sites {
					unionSites[site.ID] = goLoaderSiteSummary(site)
				}
			}
			if wholeEdges := edgeKeys(wholeResult); !reflect.DeepEqual(unionEdges, wholeEdges) {
				t.Fatalf("edge union differs from the whole chunk: union=%d whole=%d", len(unionEdges), len(wholeEdges))
			}
			wholeSites := map[string]string{}
			for _, site := range wholeResult.Sites {
				wholeSites[site.ID] = goLoaderSiteSummary(site)
			}
			if !reflect.DeepEqual(unionSites, wholeSites) {
				t.Fatalf("site union differs from the whole chunk: union=%d whole=%d", len(unionSites), len(wholeSites))
			}
		})
	}
}

func stagedNodeJSON(t *testing.T, node Node) string {
	t.Helper()
	encoded, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func stagedEndpointIDs(result Result) map[string]bool {
	endpoints := map[string]bool{}
	for _, edge := range result.Edges {
		endpoints[edge.Source] = true
		endpoints[edge.Target] = true
	}
	for _, site := range result.Sites {
		endpoints[site.Source] = true
		for _, target := range site.TargetIDs {
			endpoints[target] = true
		}
	}
	return endpoints
}
