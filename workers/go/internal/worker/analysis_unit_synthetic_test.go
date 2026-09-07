package worker

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestSyntheticAnalysisUnitCanonicalProjection exercises the source-batch
// contract with a generated, public fixture. The app module deliberately has
// one large package, while the repository also contains independent modules
// and two local directories declaring the same module path. The comparison
// treats chunk and execution order as scheduling details and keeps graph
// identities, relations, evidence, conditions, and stage-level profile axes.
func TestSyntheticAnalysisUnitCanonicalProjection(t *testing.T) {
	fixture := writeSyntheticAnalysisFixture(t, 48, 8)

	allRequest := fixture.request(fixture.sourcePaths, AnalysisUnitStageSyntax, "all", 0, 1, []string{"app/go.mod"})
	started := time.Now()
	allSampler := startSyntheticResourceSampler()
	all, err := ScanWithAnalysisUnitProgress(fixture.root, "", allRequest, nil)
	allElapsed := time.Since(started)
	allRSS := allSampler.stop()
	if err != nil {
		t.Fatalf("single source batch failed: %v", err)
	}

	const chunkSize = 7
	requests := fixture.sourceBatchRequests(chunkSize)
	started = time.Now()
	splitSampler := startSyntheticResourceSampler()
	split, progress := runSyntheticRequests(t, fixture.root, requests)
	splitElapsed := time.Since(started)
	splitRSS := splitSampler.stop()
	t.Logf("synthetic analysis stage=syntax partition=single source_files=%d modules=%d elapsed_ms=%d peak_rss_bytes=%d", len(fixture.sourcePaths), fixture.moduleCount, allElapsed.Milliseconds(), allRSS)
	t.Logf("synthetic analysis stage=syntax partition=%d-file-batches chunks=%d elapsed_ms=%d peak_rss_bytes=%d progress_events=%d", chunkSize, len(requests), splitElapsed.Milliseconds(), splitRSS, len(progress))
	if len(progress) == 0 {
		t.Fatal("source-batch scans did not emit progress callbacks")
	}

	if got := countNodesByKind(all.Nodes, "package_instance"); got < fixture.expectedContextModules {
		t.Fatalf("single batch selected %d context modules, want at least %d", got, fixture.expectedContextModules)
	}
	if got := countNodesByKind(all.Nodes, "file"); got != len(fixture.sourcePaths) {
		t.Fatalf("single batch emitted %d file nodes, want %d owned source files", got, len(fixture.sourcePaths))
	}
	assertSyntheticSourceScope(t, all, fixture.unitRoot, fixture.sourcePaths)
	assertSyntheticLocalReplacement(t, all)

	baselineProjection, err := syntheticCanonicalProjection([]Result{all})
	if err != nil {
		t.Fatalf("normalize single-batch graph: %v", err)
	}
	splitProjection, err := syntheticCanonicalProjection(split)
	if err != nil {
		t.Fatalf("normalize split graph: %v", err)
	}
	if got, want := splitProjection.String(), baselineProjection.String(); got != want {
		t.Fatalf("single and split source graphs differ after canonical normalization:\n--- split ---\n%s\n--- single ---\n%s", got, want)
	}

	reversed := append([]AnalysisUnitRequest(nil), requests...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	reversedResults, reverseProgress := runSyntheticRequests(t, fixture.root, reversed)
	reversedProjection, err := syntheticCanonicalProjection(reversedResults)
	if err != nil {
		t.Fatalf("normalize reverse-order graph: %v", err)
	}
	if got, want := reversedProjection.String(), baselineProjection.String(); got != want {
		t.Fatalf("reverse-order source graph differs after canonical normalization:\n--- reverse ---\n%s\n--- single ---\n%s", got, want)
	}
	if len(reverseProgress) != len(progress) {
		t.Fatalf("reverse-order progress event count = %d, want %d", len(reverseProgress), len(progress))
	}

	// Without a split binding the semantic stage remains one full-module
	// operation: this is the pre-#463 baseline a legacy request still gets. It
	// shares the same fixture and context but never claims to be a source batch.
	// Package-bounded requests are covered by analysis_split_scan_test.go and
	// go_loader_scan_test.go; scripts/go-loader-scope-e2e.mjs measures both
	// paths against each other at one reduced memory limit.
	semanticRequest := fixture.request(fixture.sourcePaths, AnalysisUnitStageSemantic, "semantic", 0, 1, nil)
	semanticProgress := make([]syntheticProgressEvent, 0)
	started = time.Now()
	semanticSampler := startSyntheticResourceSampler()
	semantic, err := ScanWithAnalysisUnitProgress(fixture.root, "", semanticRequest, func(phase, status string, items int) {
		semanticProgress = append(semanticProgress, syntheticProgressEvent{Phase: phase, Status: status, Items: items})
	})
	semanticElapsed := time.Since(started)
	semanticRSS := semanticSampler.stop()
	if err != nil {
		t.Fatalf("full-module semantic stage failed: %v", err)
	}
	if semantic.Profile.Properties["analysis_scope"] != "full_module" {
		t.Fatalf("semantic stage scope = %q, want full_module", semantic.Profile.Properties["analysis_scope"])
	}
	if semantic.Profile.Properties["analysis_stage"] != string(AnalysisUnitStageSemantic) {
		t.Fatalf("semantic stage property missing: %+v", semantic.Profile.Properties)
	}
	if !hasSyntheticProgress(semanticProgress, "go_typed_load") {
		t.Fatal("semantic stage did not report go_typed_load progress")
	}
	if !hasSyntheticProgress(semanticProgress, "go_ssa") {
		t.Fatal("semantic stage did not report go_ssa progress")
	}
	if !hasSyntheticProgress(semanticProgress, "go_ssa_mapping") {
		t.Fatal("semantic stage did not report go_ssa_mapping progress")
	}
	if semantic.Profile.Properties["go_packages_status"] != "loaded" {
		t.Fatalf("semantic stage did not retain typed package inventory: status=%q diagnostics=%+v", semantic.Profile.Properties["go_packages_status"], semantic.Diagnostics)
	}
	t.Logf("synthetic analysis stage=semantic scope=full_module source_files=%d elapsed_ms=%d peak_rss_bytes=%d typed_modules=%s typed_packages=%s typed_files=%s ssa_progress_events=%d", len(fixture.sourcePaths), semanticElapsed.Milliseconds(), semanticRSS, semantic.Profile.Properties["go_packages_modules"], semantic.Profile.Properties["go_packages_typed_packages"], semantic.Profile.Properties["go_packages_typed_files"], countSyntheticProgress(semanticProgress, "go_ssa"))

	// Loading the dependency closure once per semantic unit is intentional. A
	// second semantic unit that owns the replaced module should report the same
	// local file again, which makes the amount of cross-unit duplicate loading
	// visible instead of implying a cache that the worker does not provide.
	sameASemanticRequest := AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:synthetic-same-a",
		Adapter:            AdapterName,
		UnitRoot:           "same-a",
		SourcePaths:        []string{"same-a/shared.go"},
		Stage:              AnalysisUnitStageSemantic,
		ContextPaths:       []string{"same-a/shared.go"},
		ChunkID:            "semantic",
		ChunkCount:         1,
		ContextFingerprint: "sha256:synthetic-same-a-context-v1",
	}
	sameASemantic, err := ScanWithAnalysisUnit(fixture.root, "", sameASemanticRequest)
	if err != nil {
		t.Fatalf("full-module semantic stage for replaced module failed: %v", err)
	}
	if sameASemantic.Profile.Properties["go_packages_status"] != "loaded" {
		t.Fatalf("replaced-module semantic stage did not retain typed package inventory: status=%q diagnostics=%+v", sameASemantic.Profile.Properties["go_packages_status"], sameASemantic.Diagnostics)
	}
	appTypedFiles := syntheticProfileInt(t, semantic.Profile, "go_packages_typed_files")
	sameATypedFiles := syntheticProfileInt(t, sameASemantic.Profile, "go_packages_typed_files")
	uniqueContextFiles := len(fixture.contextPaths)
	duplicateTypedFiles := appTypedFiles + sameATypedFiles - uniqueContextFiles
	if duplicateTypedFiles < 0 {
		t.Fatalf("typed load accounting became negative: app=%d same-a=%d unique=%d", appTypedFiles, sameATypedFiles, uniqueContextFiles)
	}
	t.Logf("synthetic analysis typed_load_requests=%d typed_files_total=%d unique_context_files=%d duplicate_typed_files=%d reused_typed_files=%d", 2, appTypedFiles+sameATypedFiles, uniqueContextFiles, duplicateTypedFiles, 0)

	// A duplicate module path is only a collision if the repository-relative
	// module instance is omitted from identity. Scan both copies as independent
	// units to keep this property covered by the same public fixture.
	sameA := fixture.scanDuplicateModule(t, "same-a")
	sameB := fixture.scanDuplicateModule(t, "same-b")
	sameANode := findNodeProperty(sameA.Nodes, "package_instance", "relative_dir", "same-a")
	sameBNode := findNodeProperty(sameB.Nodes, "package_instance", "relative_dir", "same-b")
	if sameANode == nil || sameBNode == nil || sameANode.ID == sameBNode.ID {
		t.Fatalf("same module path instances collided: same-a=%+v same-b=%+v", sameANode, sameBNode)
	}
	typedFiles := semantic.Profile.Properties["go_packages_typed_files"]
	if typedFiles == "" {
		t.Fatalf("semantic profile omitted typed load volume: %+v", semantic.Profile.Properties)
	}
	if len(semanticProgress) == 0 {
		t.Fatal("semantic stage emitted no progress events")
	}
}

type syntheticGoFixture struct {
	root                   string
	unitRoot               string
	sourcePaths            []string
	contextPaths           []string
	moduleCount            int
	expectedContextModules int
}

func writeSyntheticAnalysisFixture(t *testing.T, sourceFileCount, dependencyModuleCount int) syntheticGoFixture {
	t.Helper()
	if sourceFileCount < 1 || dependencyModuleCount < 1 {
		t.Fatalf("synthetic fixture sizes must be positive: files=%d modules=%d", sourceFileCount, dependencyModuleCount)
	}
	root := canonicalTestRoot(t, t.TempDir())
	const (
		appModulePath  = "example.test/mega/app"
		sameModulePath = "example.test/mega/shared"
	)

	appGoMod := "module " + appModulePath + "\n\ngo 1.26.1\n\nrequire (\n"
	for index := 0; index < dependencyModuleCount; index++ {
		appGoMod += fmt.Sprintf("\texample.test/mega/dep%02d v0.0.0\n", index)
	}
	appGoMod += "\texample.test/mega/shared v0.0.0\n)\n\n"
	for index := 0; index < dependencyModuleCount; index++ {
		appGoMod += fmt.Sprintf("replace example.test/mega/dep%02d => ../dep-%02d\n", index, index)
	}
	appGoMod += "replace " + sameModulePath + " => ../same-a\n"
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), appGoMod)

	imports := make([]string, 0, dependencyModuleCount+1)
	imports = append(imports, "shared \""+sameModulePath+"\"")
	for index := 0; index < dependencyModuleCount; index++ {
		imports = append(imports, fmt.Sprintf("dep%02d \"example.test/mega/dep%02d\"", index, index))
	}
	entry := "package app\n\nimport (\n\t" + strings.Join(imports, "\n\t") + "\n)\n\nfunc Entry() int {\n\treturn shared.Value()"
	for index := 0; index < dependencyModuleCount; index++ {
		entry += fmt.Sprintf(" + dep%02d.Value()", index)
	}
	entry += "\n}\n"
	writeTestFile(t, filepath.Join(root, "app", "file00.go"), entry)
	for index := 1; index < sourceFileCount; index++ {
		contents := fmt.Sprintf("package app\n\nfunc Item%02d() int { return %d }\n", index, index)
		if index == 1 {
			contents = "//go:build !never\n\n" + contents
		}
		writeTestFile(t, filepath.Join(root, "app", fmt.Sprintf("file%02d.go", index)), contents)
	}

	for _, relativeDir := range []string{"same-a", "same-b"} {
		writeTestFile(t, filepath.Join(root, relativeDir, "go.mod"), "module "+sameModulePath+"\n\ngo 1.26.1\n")
		writeTestFile(t, filepath.Join(root, relativeDir, "shared.go"), "package shared\n\nfunc Value() int { return 7 }\n")
	}
	for index := 0; index < dependencyModuleCount; index++ {
		relativeDir := fmt.Sprintf("dep-%02d", index)
		modulePath := fmt.Sprintf("example.test/mega/dep%02d", index)
		packageName := fmt.Sprintf("dep%02d", index)
		writeTestFile(t, filepath.Join(root, relativeDir, "go.mod"), "module "+modulePath+"\n\ngo 1.26.1\n")
		writeTestFile(t, filepath.Join(root, relativeDir, "dep.go"), fmt.Sprintf("package %s\n\nfunc Value() int { return %d }\n", packageName, index+1))
	}

	sourcePaths := make([]string, 0, sourceFileCount)
	for index := 0; index < sourceFileCount; index++ {
		sourcePaths = append(sourcePaths, filepath.ToSlash(filepath.Join("app", fmt.Sprintf("file%02d.go", index))))
	}
	contextPaths := append([]string(nil), sourcePaths...)
	contextPaths = append(contextPaths, "same-a/shared.go")
	for index := 0; index < dependencyModuleCount; index++ {
		contextPaths = append(contextPaths, fmt.Sprintf("dep-%02d/dep.go", index))
	}
	sort.Strings(contextPaths)

	return syntheticGoFixture{
		root: root, unitRoot: "app", sourcePaths: sourcePaths, contextPaths: contextPaths,
		moduleCount:            dependencyModuleCount + 3, // app, same-a, same-b, and dependencies
		expectedContextModules: dependencyModuleCount + 2, // app, same-a, and dependencies
	}
}

func (fixture syntheticGoFixture) request(sourcePaths []string, stage AnalysisUnitStage, chunkID string, chunkIndex, chunkCount int, auxiliary []string) AnalysisUnitRequest {
	return AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:synthetic-app",
		Adapter:            AdapterName,
		UnitRoot:           fixture.unitRoot,
		SourcePaths:        append([]string(nil), sourcePaths...),
		Stage:              stage,
		ContextPaths:       append([]string(nil), fixture.contextPaths...),
		ChunkID:            chunkID,
		ChunkIndex:         chunkIndex,
		ChunkCount:         chunkCount,
		AuxiliaryPaths:     append([]string(nil), auxiliary...),
		ContextFingerprint: "sha256:synthetic-analysis-context-v1",
	}
}

func (fixture syntheticGoFixture) sourceBatchRequests(chunkSize int) []AnalysisUnitRequest {
	chunkCount := (len(fixture.sourcePaths) + chunkSize - 1) / chunkSize
	requests := make([]AnalysisUnitRequest, 0, chunkCount)
	for chunkIndex, start := 0, 0; start < len(fixture.sourcePaths); chunkIndex, start = chunkIndex+1, start+chunkSize {
		end := start + chunkSize
		if end > len(fixture.sourcePaths) {
			end = len(fixture.sourcePaths)
		}
		auxiliary := []string(nil)
		if chunkIndex == 0 {
			auxiliary = []string{"app/go.mod"}
		}
		requests = append(requests, fixture.request(fixture.sourcePaths[start:end], AnalysisUnitStageSyntax, fmt.Sprintf("chunk-%02d-of-%02d", chunkIndex, chunkCount), chunkIndex, chunkCount, auxiliary))
	}
	return requests
}

func (fixture syntheticGoFixture) scanDuplicateModule(t *testing.T, relativeDir string) Result {
	t.Helper()
	path := relativeDir + "/shared.go"
	request := AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:synthetic-" + relativeDir,
		Adapter:            AdapterName,
		UnitRoot:           relativeDir,
		SourcePaths:        []string{path},
		Stage:              AnalysisUnitStageSyntax,
		ContextPaths:       []string{path},
		ChunkID:            "single",
		ChunkCount:         1,
		AuxiliaryPaths:     []string{relativeDir + "/go.mod"},
		ContextFingerprint: "sha256:synthetic-" + relativeDir,
	}
	result, err := ScanWithAnalysisUnit(fixture.root, "", request)
	if err != nil {
		t.Fatalf("scan duplicate module %s: %v", relativeDir, err)
	}
	return result
}

type syntheticProgressEvent struct {
	Phase  string
	Status string
	Items  int
}

func runSyntheticRequests(t *testing.T, root string, requests []AnalysisUnitRequest) ([]Result, []syntheticProgressEvent) {
	t.Helper()
	results := make([]Result, 0, len(requests))
	progress := make([]syntheticProgressEvent, 0)
	for _, request := range requests {
		result, err := ScanWithAnalysisUnitProgress(root, "", request, func(phase, status string, items int) {
			progress = append(progress, syntheticProgressEvent{Phase: phase, Status: status, Items: items})
		})
		if err != nil {
			t.Fatalf("synthetic source batch %s failed: %v", request.ChunkID, err)
		}
		results = append(results, result)
	}
	return results, progress
}

func syntheticProfileInt(t *testing.T, profile Profile, key string) int {
	t.Helper()
	value, ok := profile.Properties[key]
	if !ok {
		t.Fatalf("profile omitted %s: %+v", key, profile.Properties)
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		t.Fatalf("profile %s = %q is not a non-negative integer", key, value)
	}
	return parsed
}

func hasSyntheticProgress(events []syntheticProgressEvent, phase string) bool {
	for _, event := range events {
		if event.Phase == phase {
			return true
		}
	}
	return false
}

func countSyntheticProgress(events []syntheticProgressEvent, phase string) int {
	count := 0
	for _, event := range events {
		if event.Phase == phase {
			count++
		}
	}
	return count
}

func countNodesByKind(nodes []Node, kind string) int {
	count := 0
	for _, node := range nodes {
		if node.Kind == kind {
			count++
		}
	}
	return count
}

func assertSyntheticSourceScope(t *testing.T, result Result, unitRoot string, sourcePaths []string) {
	t.Helper()
	owned := map[string]bool{}
	for _, path := range sourcePaths {
		owned[path] = true
	}
	owned[unitRoot+"/go.mod"] = true
	for _, file := range result.Files {
		if !owned[file.Path] {
			t.Fatalf("source batch emitted out-of-scope file completion: %+v", file)
		}
	}
	for _, node := range result.Nodes {
		if node.Kind != "file" {
			continue
		}
		path := strings.TrimPrefix(node.Locator, "file:")
		if !owned[path] || path == unitRoot+"/go.mod" {
			t.Fatalf("source batch emitted out-of-scope file node: %+v", node)
		}
	}
	for _, site := range result.Sites {
		if len(site.Evidence) == 0 {
			continue
		}
		for _, evidence := range site.Evidence {
			if !owned[evidence.Path] {
				t.Fatalf("source batch emitted out-of-scope evidence: %+v", site)
			}
		}
	}
}

func assertSyntheticLocalReplacement(t *testing.T, result Result) {
	t.Helper()
	foundRequirement := false
	foundImport := false
	nodes := make(map[string]Node, len(result.Nodes))
	for _, node := range result.Nodes {
		nodes[node.ID] = node
	}
	for _, site := range result.Sites {
		if site.Specifier != "example.test/mega/shared" {
			continue
		}
		if site.Kind == "module_requirement" {
			foundRequirement = site.ResolutionStatus == "resolved"
		}
		if site.Kind == "import" {
			foundImport = site.ResolutionStatus == "resolved"
		}
		for _, targetID := range site.TargetIDs {
			if target := nodes[targetID]; target.Kind == "package_instance" && target.Properties["relative_dir"] == "same-b" {
				t.Fatalf("local replacement resolved to the duplicate module instance: %+v", site)
			}
		}
	}
	if !foundRequirement || !foundImport {
		t.Fatalf("local replacement sites were not both resolved: requirement=%v import=%v sites=%+v", foundRequirement, foundImport, result.Sites)
	}
}

type syntheticGraphProjection struct {
	Nodes      []string `json:"nodes"`
	Sites      []string `json:"sites"`
	Edges      []string `json:"edges"`
	Files      []string `json:"files"`
	Profiles   []string `json:"profiles"`
	Conditions []string `json:"conditions"`
	Coverage   string   `json:"coverage"`
}

func (projection syntheticGraphProjection) String() string {
	encoded, _ := json.Marshal(projection)
	return string(encoded)
}

func syntheticCanonicalProjection(results []Result) (syntheticGraphProjection, error) {
	projection := syntheticGraphProjection{}
	if len(results) == 0 {
		return projection, nil
	}

	nodePayloads := map[string]string{}
	nodeKeysByID := map[string]string{}
	for _, result := range results {
		for _, node := range result.Nodes {
			identity := syntheticNodeIdentity(node)
			payload := syntheticNodePayload(node)
			if previous, ok := nodePayloads[identity]; ok && previous != payload {
				return projection, fmt.Errorf("node payload conflict for %s: %s != %s", identity, previous, payload)
			}
			nodePayloads[identity] = payload
			nodeKeysByID[node.ID] = identity
		}
	}
	for identity, payload := range nodePayloads {
		projection.Nodes = append(projection.Nodes, identity+"="+payload)
	}

	siteKeysByID := map[string]string{}
	for _, result := range results {
		for _, site := range result.Sites {
			key, err := syntheticSiteKey(site, nodeKeysByID)
			if err != nil {
				return projection, err
			}
			siteKeysByID[site.ID] = key
			projection.Sites = appendUniqueString(projection.Sites, key)
			projection.Conditions = appendUniqueString(projection.Conditions, syntheticConditionJSON(site.Condition))
		}
	}
	for _, result := range results {
		for _, edge := range result.Edges {
			key, err := syntheticEdgeKey(edge, nodeKeysByID, siteKeysByID)
			if err != nil {
				return projection, err
			}
			projection.Edges = appendUniqueString(projection.Edges, key)
			projection.Conditions = appendUniqueString(projection.Conditions, syntheticConditionJSON(edge.Condition))
		}
		for _, file := range result.Files {
			payload, err := syntheticJSON(file)
			if err != nil {
				return projection, err
			}
			projection.Files = appendUniqueString(projection.Files, file.Path+"="+payload)
		}
		profile, err := syntheticProfileKey(result.Profile)
		if err != nil {
			return projection, err
		}
		projection.Profiles = appendUniqueString(projection.Profiles, profile)
		projection.Coverage = syntheticCoverageKey(projection.Coverage, result.Coverage)
	}
	sort.Strings(projection.Nodes)
	sort.Strings(projection.Sites)
	sort.Strings(projection.Edges)
	sort.Strings(projection.Files)
	sort.Strings(projection.Profiles)
	sort.Strings(projection.Conditions)
	return projection, nil
}

func syntheticNodeIdentity(node Node) string {
	properties := cloneAnyMap(node.Properties)
	switch node.Kind {
	case "workspace":
		return node.Kind + "|" + node.Locator
	case "package_instance":
		return node.Kind + "|" + stringProperty(properties, "module_path") + "|" + stringProperty(properties, "relative_dir")
	case "module":
		return node.Kind + "|" + stringProperty(properties, "module_path") + "|" + stringProperty(properties, "relative_dir") + "|" + stringProperty(properties, "package_path")
	case "file":
		return node.Kind + "|" + node.Locator
	case "build_unit":
		return node.Kind + "|" + node.Locator + "|" + stringProperty(properties, "variant")
	default:
		return node.Kind + "|" + node.Locator + "|" + node.DisplayName
	}
}

func syntheticNodePayload(node Node) string {
	properties := cloneAnyMap(node.Properties)
	if node.Kind == "build_unit" {
		delete(properties, "profile_id")
	}
	payload, _ := syntheticJSON(map[string]any{
		"kind": node.Kind, "locator": node.Locator, "display_name": node.DisplayName, "properties": properties,
	})
	return payload
}

func syntheticSiteKey(site Site, nodeKeysByID map[string]string) (string, error) {
	targets, err := syntheticNodeTargetKeys(site.TargetIDs, nodeKeysByID)
	if err != nil {
		return "", err
	}
	source := nodeKeysByID[site.Source]
	if source == "" {
		return "", fmt.Errorf("site %s references unknown source node %q", site.ID, site.Source)
	}
	payload, err := syntheticJSON(map[string]any{
		"source": source, "kind": site.Kind, "specifier": site.Specifier, "resolution_status": site.ResolutionStatus,
		"target_keys": targets, "condition": canonicalCondition(site.Condition), "precision": site.Precision,
		"evidence": site.Evidence, "reason": site.Reason,
	})
	if err != nil {
		return "", err
	}
	return payload, nil
}

func syntheticEdgeKey(edge Edge, nodeKeysByID map[string]string, siteKeysByID map[string]string) (string, error) {
	source := nodeKeysByID[edge.Source]
	target := nodeKeysByID[edge.Target]
	if source == "" || target == "" {
		return "", fmt.Errorf("edge %s references unknown node source=%q target=%q", edge.ID, edge.Source, edge.Target)
	}
	site := ""
	if edge.SiteID != "" {
		site = siteKeysByID[edge.SiteID]
		if site == "" {
			return "", fmt.Errorf("edge %s references unknown site %q", edge.ID, edge.SiteID)
		}
	}
	payload, err := syntheticJSON(map[string]any{
		"source": source, "target": target, "kind": edge.Kind, "site": site, "phase": edge.Phase,
		"environment": edge.Environment, "resolution_status": edge.ResolutionStatus, "condition": canonicalCondition(edge.Condition),
		"precision": edge.Precision, "generated": edge.Generated, "evidence": edge.Evidence,
	})
	if err != nil {
		return "", err
	}
	return payload, nil
}

func syntheticNodeTargetKeys(ids []string, nodeKeysByID map[string]string) ([]string, error) {
	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		key := nodeKeysByID[id]
		if key == "" {
			return nil, fmt.Errorf("target references unknown node %q", id)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

func syntheticProfileKey(profile Profile) (string, error) {
	properties := map[string]string{}
	for key, value := range profile.Properties {
		if strings.HasPrefix(key, "analysis_chunk_") || key == "analysis_source_path_count" || strings.HasPrefix(key, "go_callgraph_boundary_") {
			continue
		}
		properties[key] = value
	}
	return syntheticJSON(map[string]any{
		"language": profile.Language, "toolchain": profile.Toolchain, "command": profile.Command, "target": profile.Target,
		"features": profile.Features, "environment": profile.Environment, "properties": properties,
	})
}

func syntheticCoverageKey(previous string, coverage Coverage) string {
	var aggregate Coverage
	if previous != "" {
		_ = json.Unmarshal([]byte(previous), &aggregate)
	}
	aggregate.Profiles = 1
	aggregate.FilesDiscovered += coverage.FilesDiscovered
	aggregate.FilesAnalyzed += coverage.FilesAnalyzed
	aggregate.FilesSkipped += coverage.FilesSkipped
	aggregate.DependencySites += coverage.DependencySites
	aggregate.Resolved += coverage.Resolved
	aggregate.Candidates += coverage.Candidates
	aggregate.External += coverage.External
	aggregate.Unresolved += coverage.Unresolved
	aggregate.UnsupportedSyntax += coverage.UnsupportedSyntax
	aggregate.ProjectCodeExecuted = aggregate.ProjectCodeExecuted || coverage.ProjectCodeExecuted
	aggregate.Completeness = appendUniqueString(aggregate.Completeness, coverage.Completeness...)
	aggregate.Reasons = appendUniqueString(aggregate.Reasons, coverage.Reasons...)
	sort.Strings(aggregate.Completeness)
	sort.Strings(aggregate.Reasons)
	encoded, _ := json.Marshal(aggregate)
	return string(encoded)
}

func syntheticConditionJSON(condition Condition) string {
	encoded, _ := syntheticJSON(canonicalCondition(condition))
	return encoded
}

func syntheticJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func cloneAnyMap(source map[string]any) map[string]any {
	if source == nil {
		return map[string]any{}
	}
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func stringProperty(properties map[string]any, key string) string {
	value, _ := properties[key].(string)
	return value
}

func appendUniqueString(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	return values
}

type syntheticResourceSampler struct {
	stopCh chan struct{}
	doneCh chan struct{}
	maxRSS atomic.Int64
}

func startSyntheticResourceSampler() *syntheticResourceSampler {
	sampler := &syntheticResourceSampler{stopCh: make(chan struct{}), doneCh: make(chan struct{})}
	go func() {
		defer close(sampler.doneCh)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rss := syntheticProcessRSSBytes()
				for {
					previous := sampler.maxRSS.Load()
					if rss <= previous || sampler.maxRSS.CompareAndSwap(previous, rss) {
						break
					}
				}
			case <-sampler.stopCh:
				return
			}
		}
	}()
	return sampler
}

func (sampler *syntheticResourceSampler) stop() int64 {
	if sampler == nil {
		return 0
	}
	close(sampler.stopCh)
	<-sampler.doneCh
	if value := sampler.maxRSS.Load(); value > 0 {
		return value
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return int64(memory.Sys)
}

func syntheticProcessRSSBytes() int64 {
	if runtime.GOOS == "windows" {
		return 0
	}
	output, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return 0
	}
	kib, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || kib < 0 {
		return 0
	}
	return kib * 1024
}
