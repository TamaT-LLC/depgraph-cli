package worker

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestScanWorkspaceFixture(t *testing.T) {
	root := fixtureRoot(t)
	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if result.Coverage.ProjectCodeExecuted {
		t.Fatal("safe scan reported project code execution")
	}
	if result.Coverage.FilesDiscovered != 13 || result.Coverage.FilesAnalyzed != 13 || result.Coverage.FilesSkipped != 0 {
		t.Fatalf("unexpected file coverage: %+v", result.Coverage)
	}
	classified := result.Coverage.Resolved + result.Coverage.Candidates + result.Coverage.External + result.Coverage.Unresolved
	if classified != result.Coverage.DependencySites || classified != len(result.Sites) {
		t.Fatalf("site ledger mismatch: coverage=%+v sites=%d", result.Coverage, len(result.Sites))
	}
	if result.Coverage.Resolved == 0 || result.Coverage.Candidates == 0 || result.Coverage.External == 0 || result.Coverage.Unresolved == 0 {
		t.Fatalf("fixture should cover all resolution statuses: %+v", result.Coverage)
	}

	assertSiteStatus(t, result.Sites, "module_requirement", "example.com/shared", "resolved")
	assertSiteStatus(t, result.Sites, "module_requirement", "example.com/old", "resolved")
	assertSiteStatus(t, result.Sites, "module_requirement", "example.net/external", "external")
	assertSiteStatus(t, result.Sites, "import", "example.com/app/lib", "resolved")
	assertSiteStatus(t, result.Sites, "import", "example.net/vendored/pkg", "resolved")
	assertSiteStatus(t, result.Sites, "side_effect_import", "./legacy-relative-import", "unresolved")
	assertSiteStatus(t, result.Sites, "embed", "assets/*.txt", "candidates")
	assertSiteStatus(t, result.Sites, "cgo_import", "C", "external")
	assertSiteStatus(t, result.Sites, "cgo_library", "m", "external")
	assertSiteStatus(t, result.Sites, "cgo_header", "<stdlib.h>", "external")

	buildConditionFound := false
	for _, site := range result.Sites {
		if strings.HasSuffix(site.Evidence[0].Path, "app/lib/lib.go") && site.Condition.Op == "all" && len(site.Condition.Conditions) > 0 {
			buildConditionFound = true
		}
	}
	if !buildConditionFound {
		t.Fatal("dependencies from build-constrained file did not retain the condition AST")
	}

	generatedFound := false
	variants := map[string]bool{}
	nodesByID := map[string]Node{}
	sitesByID := map[string]Site{}
	for _, node := range result.Nodes {
		nodesByID[node.ID] = node
		if !strings.Contains(node.ID, ":sha256:") {
			t.Fatalf("node ID does not use canonical sha256 format: %s", node.ID)
		}
		if node.Kind == "package_instance" {
			modulePath, ok := node.Properties["module_path"].(string)
			if !ok {
				t.Fatalf("package %q has no string module_path", node.ID)
			}
			wantManifest, ok := map[string]string{
				"example.com/app":      "app/go.mod",
				"example.com/shared":   "shared/go.mod",
				"example.com/replaced": "replaced/go.mod",
			}[modulePath]
			if !ok {
				t.Fatalf("unexpected package module_path %q", modulePath)
			}
			if got, _ := node.Properties["manifest_path"].(string); got != wantManifest {
				t.Fatalf("package %q manifest_path = %q, want %q", modulePath, got, wantManifest)
			}
		}
		if node.Kind == "module" && strings.HasPrefix(node.Locator, "go-package:") {
			packagePath, ok := node.Properties["package_path"].(string)
			if !ok || packagePath != strings.TrimPrefix(node.Locator, "go-package:") {
				t.Fatalf("Go package %q package_path = %q, want locator path", node.ID, packagePath)
			}
		}
		if node.Kind == "file" && strings.HasSuffix(node.Locator, "app/lib/generated.go") {
			generatedFound, _ = node.Properties["generated"].(bool)
		}
		if node.Kind == "file" && node.Properties["language"] == "go" {
			relativePath := strings.TrimPrefix(node.Locator, "file:")
			wantManifest := ""
			switch {
			case strings.HasPrefix(relativePath, "app/"):
				wantManifest = "app/go.mod"
			case strings.HasPrefix(relativePath, "shared/"):
				wantManifest = "shared/go.mod"
			case strings.HasPrefix(relativePath, "replaced/"):
				wantManifest = "replaced/go.mod"
			}
			if wantManifest == "" {
				t.Fatalf("Go file %q is outside the fixture module roots", node.ID)
			}
			if got, _ := node.Properties["manifest_path"].(string); got != wantManifest {
				t.Fatalf("Go file %q manifest_path = %q, want %q", node.ID, got, wantManifest)
			}
		}
		if node.Kind == "build_unit" && strings.HasPrefix(node.Locator, "go-unit:example.com/app/lib#") {
			variants[node.Properties["variant"].(string)] = true
		}
	}
	for _, site := range result.Sites {
		sitesByID[site.ID] = site
		if !strings.Contains(site.ID, ":sha256:") {
			t.Fatalf("site ID does not use canonical sha256 format: %s", site.ID)
		}
		if site.ResolutionStatus == "external" {
			if target := nodesByID[site.TargetIDs[0]]; target.Kind != "external_system" {
				t.Fatalf("external site targets %q instead of external_system: %+v", target.Kind, site)
			}
		}
		wantNativeLocator := ""
		switch site.Kind {
		case "cgo_import":
			wantNativeLocator = "native-toolchain:c"
		case "cgo_library":
			wantNativeLocator = "native-library:m"
		case "cgo_header":
			wantNativeLocator = "native-header:<stdlib.h>"
		}
		if wantNativeLocator != "" {
			target := nodesByID[site.TargetIDs[0]]
			if target.Locator != wantNativeLocator || target.Properties["native_kind"] == "" ||
				site.Evidence[0].Properties["callgraph_boundary"] == "" {
				t.Fatalf("native boundary identity was not normalized: want=%q site=%+v target=%+v", wantNativeLocator, site, target)
			}
		}
		for _, evidence := range site.Evidence {
			extractor := "go-static-worker"
			if evidence.Kind == "semantic" {
				extractor = "go-types"
			}
			if evidence.Extractor != extractor || evidence.ExtractorVersion != AdapterVersion {
				t.Fatalf("site evidence lacks extractor identity: %+v", evidence)
			}
		}
	}
	if got := result.Profile.Properties["go_callgraph_boundary_site_count"]; got != "3" {
		t.Fatalf("workspace native boundary count = %q, want 3: %+v", got, result.Profile.Properties)
	}
	boundaryDiagnostics := 0
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code != "go_callgraph_limit" {
			continue
		}
		boundaryDiagnostics++
		siteID, _ := diagnostic.Properties["site_id"].(string)
		if _, ok := sitesByID[siteID]; !ok {
			t.Fatalf("native boundary diagnostic has no site: %+v", diagnostic)
		}
	}
	if boundaryDiagnostics != 3 {
		t.Fatalf("workspace native boundary diagnostics = %d, want 3: %+v", boundaryDiagnostics, result.Diagnostics)
	}
	for _, edge := range result.Edges {
		if edge.Environment != "any" {
			t.Fatalf("edge lacks environment: %+v", edge)
		}
		if edge.Evidence == nil {
			t.Fatalf("edge evidence must be an array: %+v", edge)
		}
		extractor := ""
		switch edge.Phase {
		case "source":
			extractor = "go-static-worker"
		case "semantic":
			extractor = "go-types"
		default:
			t.Fatalf("edge has invalid phase: %+v", edge)
		}
		for _, evidence := range edge.Evidence {
			if evidence.Extractor != extractor || evidence.ExtractorVersion != AdapterVersion {
				t.Fatalf("edge evidence lacks extractor identity: %+v", evidence)
			}
		}
	}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.ID == "" || !strings.Contains(diagnostic.ID, ":sha256:") {
			t.Fatalf("diagnostic has no stable ID: %+v", diagnostic)
		}
	}
	if !generatedFound {
		t.Fatal("standard generated marker was not detected")
	}
	for _, variant := range []string{"normal", "internal_test", "external_test"} {
		if !variants[variant] {
			t.Fatalf("missing package variant %q; got %v", variant, variants)
		}
	}

	if _, err := os.Stat(filepath.Join(root, "app", "lib", "generator-was-run")); !os.IsNotExist(err) {
		t.Fatalf("go:generate command appears to have run: %v", err)
	}
	foundGenerateDiagnostic := false
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == "go_generate_not_executed" {
			foundGenerateDiagnostic = true
		}
	}
	if !foundGenerateDiagnostic {
		t.Fatal("go:generate non-execution was not recorded")
	}
}

func TestScanWithInventoryExcludesIgnoredNestedWorkspace(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".branches", "feature"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod":                         "module example.test/inventory\n\ngo 1.26\n",
		"main.go":                        "package inventory\n\nfunc Kept() {}\n",
		".branches/feature/go.mod":       "module example.test/ignored\n\ngo 1.26\n",
		".branches/feature/generated.go": "package ignored\n\nfunc Ignored() {}\n",
		".branches/feature/generated.s":  "TEXT ·Ignored(SB),$0-0\nRET\n",
	}
	for relative, contents := range files {
		absolute := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	inventoryFile := filepath.Join(t.TempDir(), "inventory.json")
	inventory, err := json.Marshal(repositoryInventoryDocument{
		ContractVersion: repositoryInventoryContractVersion,
		Paths:           []string{"go.mod", "main.go"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventoryFile, inventory, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ScanWithInventory(root, inventoryFile)
	if err != nil {
		t.Fatalf("ScanWithInventory() error = %v", err)
	}
	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte(".branches")) || bytes.Contains(serialized, []byte("example.test/ignored")) {
		t.Fatalf("ignored nested workspace entered the graph: %s", serialized)
	}
	if result.Coverage.FilesAnalyzed == 0 {
		t.Fatalf("tracked source was not analyzed: %+v", result.Coverage)
	}
}

func TestSiblingModulesRequireGoWorkOrLocalReplaceForResolution(t *testing.T) {
	tests := []struct {
		name      string
		goWork    string
		replace   string
		wantState string
	}{
		{name: "unrelated sibling", wantState: "external"},
		{
			name:      "go work members",
			goWork:    "go 1.26.1\n\nuse (\n\t./app\n\t./lib\n)\n",
			wantState: "resolved",
		},
		{
			name:      "module local replace",
			replace:   "\nreplace example.com/lib => ../lib\n",
			wantState: "resolved",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeTestFile(t, filepath.Join(root, "app", "go.mod"), "module example.com/app\n\ngo 1.26.1\n\nrequire example.com/lib v1.0.0\n"+test.replace)
			writeTestFile(t, filepath.Join(root, "app", "main.go"), "package app\n\nimport _ \"example.com/lib/pkg\"\n")
			writeTestFile(t, filepath.Join(root, "lib", "go.mod"), "module example.com/lib\n\ngo 1.26.1\n")
			writeTestFile(t, filepath.Join(root, "lib", "pkg", "lib.go"), "package pkg\n")
			if test.goWork != "" {
				writeTestFile(t, filepath.Join(root, "go.work"), test.goWork)
			}

			result, err := Scan(root)
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			assertSiteStatus(t, result.Sites, "module_requirement", "example.com/lib", test.wantState)
			assertSiteStatus(t, result.Sites, "side_effect_import", "example.com/lib/pkg", test.wantState)
		})
	}
}

func TestRemoteReplacementUsesResolvedPackageLocator(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), `module example.com/app

go 1.26.1

require example.com/original v1.0.0
replace example.com/original v1.0.0 => example.net/fork v2.3.4
`)
	writeTestFile(t, filepath.Join(root, "main.go"), "package app\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	site := findSite(result.Sites, "module_requirement", "example.com/original")
	if site == nil || site.ResolutionStatus != "external" || len(site.TargetIDs) != 1 {
		t.Fatalf("remote replacement site was not external: %+v", site)
	}
	var target *Node
	for index := range result.Nodes {
		if result.Nodes[index].ID == site.TargetIDs[0] {
			target = &result.Nodes[index]
			break
		}
	}
	if target == nil {
		t.Fatalf("replacement target %q was not emitted", site.TargetIDs[0])
	}
	if target.Locator != "gomod:example.net/fork@v2.3.4" || target.DisplayName != "example.net/fork" {
		t.Fatalf("replacement target retained the requested locator: %+v", target)
	}
	for key, expected := range map[string]string{
		"module_path":           "example.net/fork",
		"version":               "v2.3.4",
		"requested_module_path": "example.com/original",
		"requested_version":     "v1.0.0",
		"replace_path":          "example.net/fork",
		"replace_version":       "v2.3.4",
	} {
		if target.Properties[key] != expected {
			t.Fatalf("replacement target property %s=%v, want %q: %+v", key, target.Properties[key], expected, target)
		}
	}
}

func TestProfileConfigurationIsReflectedWithoutExecutingTools(t *testing.T) {
	t.Setenv("DEPGRAPH_PROFILE_CONFIG", `{"go_tags":[" linux ","integration","integration",""]}`)
	result, err := Scan(fixtureRoot(t))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !reflect.DeepEqual(result.Profile.Features, []string{"integration", "linux"}) {
		t.Fatalf("configured tags were not canonicalized: %v", result.Profile.Features)
	}
	if result.Profile.Environment["GO_TAGS"] != "integration,linux" {
		t.Fatalf("configured tags were not recorded in the environment: %+v", result.Profile.Environment)
	}
	if result.Profile.ID == "go:host:normal-tests" {
		t.Fatal("non-default profile should have a distinct stable ID")
	}
	t.Setenv("DEPGRAPH_PROFILE_CONFIG", `{"go_tags":["integration","linux"]}`)
	reordered, err := Scan(fixtureRoot(t))
	if err != nil {
		t.Fatalf("Scan() with reordered tags error = %v", err)
	}
	if reordered.Profile.ID != result.Profile.ID || !reflect.DeepEqual(reordered.Profile.Features, result.Profile.Features) {
		t.Fatalf("equivalent tag sets changed profile identity: first=%+v second=%+v", result.Profile, reordered.Profile)
	}
}

func TestProfileIdentityIncludesHostAndEffectiveCgoAxes(t *testing.T) {
	linux := goProfileID("linux", "amd64", "0", nil, "rta-cha", "complete", "snapshot-a")
	darwin := goProfileID("darwin", "amd64", "0", nil, "rta-cha", "complete", "snapshot-a")
	linuxCgo := goProfileID("linux", "amd64", "1", nil, "rta-cha", "complete", "snapshot-a")
	if linux == darwin || linux == linuxCgo || darwin == linuxCgo {
		t.Fatalf("distinct effective Go profiles collided: linux=%s darwin=%s cgo=%s", linux, darwin, linuxCgo)
	}
	first := goProfileID("linux", "amd64", "0", []string{" integration ", "linux", "integration"}, "rta-cha", "complete", "snapshot-a")
	second := goProfileID("linux", "amd64", "0", []string{"linux", "integration"}, "rta-cha", "complete", "snapshot-a")
	if first != second {
		t.Fatalf("equivalent Go tag sets changed profile identity: first=%s second=%s", first, second)
	}

	result, err := Scan(fixtureRoot(t))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Profile.ID != goProfileID(runtime.GOOS, runtime.GOARCH, "0", nil, "rta-cha", result.Profile.Properties["go_dependency_snapshot_status"], result.Profile.Properties["go_dependency_snapshot_fingerprint"]) {
		t.Fatalf("default profile omitted an effective host axis: %+v", result.Profile)
	}
	if result.Profile.Environment["CGO_ENABLED"] != "0" {
		t.Fatalf("profile did not report constrained cgo state: %+v", result.Profile.Environment)
	}
}

func TestVTAProfileIsExplicitAndIdentityScoped(t *testing.T) {
	root := fixtureRoot(t)
	defaultResult, err := Scan(root)
	if err != nil {
		t.Fatalf("default Scan() error = %v", err)
	}
	if defaultResult.Profile.Properties["go_call_graph_requested"] != "rta-cha" {
		t.Fatalf("default call graph mode = %q, want rta-cha", defaultResult.Profile.Properties["go_call_graph_requested"])
	}

	t.Setenv("DEPGRAPH_PROFILE_CONFIG", `{"go_call_graph":"vta"}`)
	vtaResult, err := Scan(root)
	if err != nil {
		t.Fatalf("VTA Scan() error = %v", err)
	}
	if vtaResult.Profile.Properties["go_call_graph_requested"] != "vta" ||
		vtaResult.Profile.ID != goProfileID(runtime.GOOS, runtime.GOARCH, "0", nil, "vta", vtaResult.Profile.Properties["go_dependency_snapshot_status"], vtaResult.Profile.Properties["go_dependency_snapshot_fingerprint"]) ||
		vtaResult.Profile.ID == defaultResult.Profile.ID {
		t.Fatalf("VTA profile was not explicitly identity-scoped: default=%+v vta=%+v", defaultResult.Profile, vtaResult.Profile)
	}

	// Direct worker invocation is fail-closed even if it bypasses core config
	// validation: an unknown analysis mode cannot silently enable VTA.
	t.Setenv("DEPGRAPH_PROFILE_CONFIG", `{"go_call_graph":"pta"}`)
	invalidResult, err := Scan(root)
	if err != nil {
		t.Fatalf("invalid direct worker profile Scan() error = %v", err)
	}
	if invalidResult.Profile.Properties["go_call_graph_requested"] != "rta-cha" || invalidResult.Profile.ID != defaultResult.Profile.ID {
		t.Fatalf("unknown direct worker mode did not fall back to the default profile: %+v", invalidResult.Profile)
	}
}

func TestLineCommentCgoPreamblePreservesDirectiveConditions(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/cgo-safe\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "cgo.go"), `package cgosafe

// #cgo linux,!windows LDFLAGS: -lm -lssl
// #include <stdlib.h>
import "C"
`)

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, library := range []string{"m", "ssl"} {
		site := findSite(result.Sites, "cgo_library", library)
		if site == nil {
			t.Fatalf("missing line-comment cgo library site %q: %+v", library, result.Sites)
		}
		for _, key := range []string{"go.build_tag:cgo", "go.build_tag:linux"} {
			if !conditionDefines(site.Condition, key) {
				t.Fatalf("cgo library %q lost condition %q: %+v", library, key, site.Condition)
			}
		}
		if !conditionNegates(site.Condition, "go.build_tag:windows") {
			t.Fatalf("cgo library %q lost !windows condition: %+v", library, site.Condition)
		}
	}
	if findSite(result.Sites, "cgo_header", "<stdlib.h>") == nil {
		t.Fatalf("missing line-comment cgo header site: %+v", result.Sites)
	}
}

func TestCgoConstraintOptionsUseOrOfCommaConjunctions(t *testing.T) {
	directive, arguments, condition, ok := parseCgoDirective("#cgo linux,amd64 darwin,!cgo LDFLAGS: -lm")
	if !ok || directive != "LDFLAGS" || arguments != "-lm" {
		t.Fatalf("parseCgoDirective() = %q %q %+v %v", directive, arguments, condition, ok)
	}
	if condition.Op != "any" || len(condition.Conditions) != 2 {
		t.Fatalf("space-separated cgo options must be OR branches: %+v", condition)
	}
	if !conditionDefines(condition, "go.build_tag:linux") || !conditionDefines(condition, "go.build_tag:amd64") || !conditionDefines(condition, "go.build_tag:darwin") {
		t.Fatalf("cgo option terms were lost: %+v", condition)
	}
	if !conditionNegates(condition, "go.build_tag:cgo") {
		t.Fatalf("negated cgo option term was lost: %+v", condition)
	}
	for _, branch := range condition.Conditions {
		if branch.Op != "all" || len(branch.Conditions) != 2 {
			t.Fatalf("each comma-separated option must remain an AND branch: %+v", condition)
		}
	}
}

func TestBrokenSourceRecordsRecoverableSkippedSiteLedger(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/broken\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "broken.go"), "package broken\n\nimport (\n\t\"fmt\"\n\t\"example.invalid/missing\"\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	var completion *FileCompletion
	for index := range result.Files {
		if result.Files[index].Path == "broken.go" {
			completion = &result.Files[index]
			break
		}
	}
	if completion == nil {
		t.Fatalf("broken source has no file completion: %+v", result.Files)
	}
	if !completion.Skipped || completion.SkippedSites != 1 || completion.Reason == "" {
		t.Fatalf("broken source lacks skipped-site reason: %+v", completion)
	}
	if completion.DiscoveredSites != completion.EmittedSites+completion.SkippedSites {
		t.Fatalf("broken source ledger is not conserved: %+v", completion)
	}
	if result.Coverage.UnsupportedSyntax == 0 || result.Coverage.FilesSkipped == 0 || result.Coverage.ProjectCodeExecuted {
		t.Fatalf("broken source coverage is not recoverable/incomplete: %+v", result.Coverage)
	}

	var output bytes.Buffer
	if err := Emit(&output, "broken-ledger", result); err != nil {
		t.Fatalf("Emit() error = %v", err)
	}
	protocolHasSkippedSites := false
	for scanner := bufio.NewScanner(&output); scanner.Scan(); {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode protocol event: %v", err)
		}
		if event["event"] == "file_completed" && event["path"] == "broken.go" {
			protocolHasSkippedSites = event["skipped_sites"] == float64(1) && event["reason"] != ""
		}
	}
	if !protocolHasSkippedSites {
		t.Fatalf("file_completed omitted skipped_sites/reason: %s", output.String())
	}
}

func TestMalformedManifestsRetainValidSitesAndConserveCoverage(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), `module example.com/malformed
go 1.26.1
require (
	example.com/kept v1.0.0
	example.com/missing-version
)
exclude example.com/unmodeled v2.0.0
`)
	writeTestFile(t, filepath.Join(root, "go.work"), `go 1.26.1
use .
godebug default=go1.26.1
replace example.com/broken =>
`)
	writeTestFile(t, filepath.Join(root, "main.go"), "package malformed\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	assertSiteStatus(t, result.Sites, "module_requirement", "example.com/kept", "external")
	if result.Coverage.UnsupportedSyntax != 4 || result.Coverage.FilesSkipped != 2 {
		t.Fatalf("malformed manifests did not make strict coverage incomplete: %+v", result.Coverage)
	}
	if !containsString(result.Coverage.Reasons, "unsupported-syntax") || !containsString(result.Coverage.Reasons, "files-skipped") {
		t.Fatalf("manifest incompleteness reasons are missing: %+v", result.Coverage.Reasons)
	}

	completions := map[string]FileCompletion{}
	for _, completion := range result.Files {
		if completion.DiscoveredSites != completion.EmittedSites+completion.SkippedSites {
			t.Fatalf("file ledger is not conserved: %+v", completion)
		}
		completions[completion.Path] = completion
	}
	if completion := completions["go.mod"]; completion.EmittedSites != 1 || completion.SkippedSites != 2 || !completion.Skipped || completion.Reason == "" {
		t.Fatalf("go.mod malformed directive ledger is incomplete: %+v", completion)
	}
	if completion := completions["go.work"]; completion.EmittedSites != 0 || completion.SkippedSites != 2 || !completion.Skipped || completion.Reason == "" {
		t.Fatalf("go.work malformed directive ledger is incomplete: %+v", completion)
	}
}

func TestManifestReadFailureUsesOneSkippedLedgerEntry(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/read-failure\ngo 1.26.1\nrequire example.com/kept v1.0.0\n"+strings.Repeat("x", 70*1024)+"\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package readfailure\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	assertSiteStatus(t, result.Sites, "module_requirement", "example.com/kept", "external")
	for _, completion := range result.Files {
		if completion.Path != "go.mod" {
			continue
		}
		if completion.EmittedSites != 1 || completion.SkippedSites != 1 || completion.DiscoveredSites != 2 || !completion.Skipped {
			t.Fatalf("manifest read failure was dropped or double-counted: %+v", completion)
		}
		if result.Coverage.UnsupportedSyntax != 0 {
			t.Fatalf("read failure was also counted as unsupported syntax: %+v", result.Coverage)
		}
		return
	}
	t.Fatalf("go.mod completion missing: %+v", result.Files)
}

func TestProfileScopedGraphIDsChangeWithEffectiveProfile(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/profiled\ngo 1.26.1\nrequire example.net/external v1.0.0\nexclude example.net/unmodeled v0.9.0\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package profiled\nimport (\n _ \"fmt\"\n _ \"./relative\"\n)\n")

	t.Setenv("DEPGRAPH_PROFILE_CONFIG", `{"go_tags":["alpha"]}`)
	alpha, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan(alpha) error = %v", err)
	}
	alphaAgain, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan(alpha again) error = %v", err)
	}
	if !reflect.DeepEqual(alpha.Nodes, alphaAgain.Nodes) || !reflect.DeepEqual(alpha.Sites, alphaAgain.Sites) || !reflect.DeepEqual(alpha.Edges, alphaAgain.Edges) || !reflect.DeepEqual(alpha.Diagnostics, alphaAgain.Diagnostics) {
		t.Fatal("same effective profile did not produce stable graph and diagnostic IDs")
	}

	t.Setenv("DEPGRAPH_PROFILE_CONFIG", `{"go_tags":["beta"]}`)
	beta, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan(beta) error = %v", err)
	}
	if alpha.Profile.ID == beta.Profile.ID {
		t.Fatalf("distinct tags shared a profile ID: %s", alpha.Profile.ID)
	}

	betaNodes := map[string]Node{}
	for _, node := range beta.Nodes {
		betaNodes[node.Kind+"\x00"+node.Locator] = node
	}
	wantScopedKinds := map[string]bool{
		"package_instance": false, "module": false, "build_unit": false, "file": false,
		"external_system": false, "unknown_target": false,
	}
	for _, node := range alpha.Nodes {
		other, ok := betaNodes[node.Kind+"\x00"+node.Locator]
		if !ok {
			t.Fatalf("profile changed logical node inventory: %+v", node)
		}
		if node.Kind == "workspace" {
			if node.ID != other.ID {
				t.Fatalf("workspace identity must remain profile-independent: alpha=%s beta=%s", node.ID, other.ID)
			}
			continue
		}
		if node.ID == other.ID {
			t.Fatalf("profile-scoped %s node reused ID %s", node.Kind, node.ID)
		}
		if _, tracked := wantScopedKinds[node.Kind]; tracked {
			wantScopedKinds[node.Kind] = true
		}
	}
	for kind, found := range wantScopedKinds {
		if !found {
			t.Fatalf("profile fixture did not exercise scoped node kind %q: %+v", kind, alpha.Nodes)
		}
	}

	betaSites := map[string]Site{}
	for _, site := range beta.Sites {
		key := site.Kind + "\x00" + site.Specifier + "\x00" + site.Evidence[0].Path + "\x00" + strconv.Itoa(site.Evidence[0].StartLine)
		betaSites[key] = site
	}
	for _, site := range alpha.Sites {
		key := site.Kind + "\x00" + site.Specifier + "\x00" + site.Evidence[0].Path + "\x00" + strconv.Itoa(site.Evidence[0].StartLine)
		other, ok := betaSites[key]
		if !ok || site.ID == other.ID || site.ProfileID == other.ProfileID {
			t.Fatalf("dependency site was not scoped to its effective profile: alpha=%+v beta=%+v", site, other)
		}
	}
	alphaEdgeIDs := map[string]bool{}
	for _, edge := range alpha.Edges {
		alphaEdgeIDs[edge.ID] = true
	}
	for _, edge := range beta.Edges {
		if alphaEdgeIDs[edge.ID] {
			t.Fatalf("edge ID was reused across effective profiles: %s", edge.ID)
		}
	}
	alphaDiagnosticIDs := map[string]bool{}
	for _, diagnostic := range alpha.Diagnostics {
		alphaDiagnosticIDs[diagnostic.ID] = true
	}
	for _, diagnostic := range beta.Diagnostics {
		if alphaDiagnosticIDs[diagnostic.ID] {
			t.Fatalf("diagnostic ID was reused across effective profiles: %s", diagnostic.ID)
		}
	}

	linuxProfile := goProfileID("linux", "amd64", "0", []string{"alpha"}, "rta-cha", "complete", "snapshot-a")
	darwinProfile := goProfileID("darwin", "amd64", "0", []string{"alpha"}, "rta-cha", "complete", "snapshot-a")
	if profileScopedID("file", "workspace", linuxProfile, "example.com/profiled", "main.go") == profileScopedID("file", "workspace", darwinProfile, "example.com/profiled", "main.go") {
		t.Fatal("host target changes did not affect a profile-scoped file ID")
	}
}

func TestScanIsStableAcrossRootLocations(t *testing.T) {
	source := fixtureRoot(t)
	rootA := filepath.Join(t.TempDir(), "checkout-a")
	rootB := filepath.Join(t.TempDir(), "unrelated", "checkout-b")
	copyTree(t, source, rootA)
	copyTree(t, source, rootB)

	a, err := Scan(rootA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Scan(rootB)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Nodes, b.Nodes) || !reflect.DeepEqual(a.Sites, b.Sites) || !reflect.DeepEqual(a.Edges, b.Edges) || !reflect.DeepEqual(a.Coverage, b.Coverage) {
		aJSON, _ := json.MarshalIndent(a, "", "  ")
		bJSON, _ := json.MarshalIndent(b, "", "  ")
		t.Fatalf("graph changed across checkout paths\nA=%s\nB=%s", aJSON, bJSON)
	}
}

func TestScanDoesNotTraverseGoWorkPathOutsideRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.23\nuse ../outside\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n")
	writeTestFile(t, filepath.Join(outside, "go.mod"), "module outside.example/module\ngo 1.23\n")
	writeTestFile(t, filepath.Join(outside, "outside.go"), "package outside\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range result.Nodes {
		if strings.Contains(node.Locator, "outside.example") {
			t.Fatalf("outside workspace was traversed: %+v", node)
		}
	}
	found := false
	for _, diagnostic := range result.Diagnostics {
		found = found || diagnostic.Code == "path_confinement"
	}
	if !found {
		t.Fatal("missing path confinement diagnostic")
	}
}

func TestEmbedSymlinkCannotEscapeRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/safe\ngo 1.26\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package safe\nimport _ \"embed\"\n//go:embed linked/*.txt\nvar content string\n")
	writeTestFile(t, filepath.Join(outside, "secret.txt"), "secret\n")
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	assertSiteStatus(t, result.Sites, "embed", "linked/*.txt", "unresolved")
	for _, node := range result.Nodes {
		if strings.Contains(node.Locator, "secret.txt") {
			t.Fatalf("embed traversal exposed an out-of-root file: %+v", node)
		}
	}
}

func TestManifestAndSourceSymlinksCannotEscapeCanonicalRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/safe\ngo 1.26\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package safe\n")
	writeTestFile(t, filepath.Join(root, "nested", "inside.go"), "package nested\n")
	writeTestFile(t, filepath.Join(outside, "secret.mod"), "module outside.example/derived-prefix\ngo 1.26\n")
	writeTestFile(t, filepath.Join(outside, "secret.work"), "go 1.26\nuse .\n")
	writeTestFile(t, filepath.Join(outside, "secret.go"), "package outsidesecret\n")
	if err := os.Symlink(filepath.Join(outside, "secret.mod"), filepath.Join(root, "nested", "go.mod")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.work"), filepath.Join(root, "go.work")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.go"), filepath.Join(root, "linked.go")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range result.Nodes {
		serialized, _ := json.Marshal(node)
		if strings.Contains(string(serialized), "outside.example") || strings.Contains(string(serialized), "outsidesecret") {
			t.Fatalf("out-of-root symlink content influenced the graph: %s", serialized)
		}
		if node.Kind == "workspace" {
			if enabled, _ := node.Properties["go_work"].(bool); enabled {
				t.Fatalf("out-of-root go.work symlink was treated as workspace metadata: %+v", node)
			}
		}
	}
	confinementDiagnostics := 0
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == "path_confinement" {
			confinementDiagnostics++
		}
	}
	if confinementDiagnostics < 2 {
		t.Fatalf("expected confinement diagnostics for go.mod and go.work symlinks: %+v", result.Diagnostics)
	}
	skipped := map[string]FileCompletion{}
	for _, completion := range result.Files {
		if completion.Skipped {
			skipped[completion.Path] = completion
		}
	}
	for _, path := range []string{
		"__depgraph_skipped__/nested/go.mod",
		"__depgraph_skipped__/go.work",
		"__depgraph_skipped__/linked.go",
	} {
		completion, ok := skipped[path]
		if !ok {
			t.Fatalf("missing skipped ledger entry for %s: %+v", path, result.Files)
		}
		if completion.DiscoveredSites != 1 || completion.EmittedSites != 0 || completion.SkippedSites != 1 || completion.Reason == "" {
			t.Fatalf("invalid skipped ledger entry for %s: %+v", path, completion)
		}
	}
	if result.Coverage.FilesSkipped < 3 || slices.Contains(result.Coverage.Completeness, "syntax-complete") {
		t.Fatalf("confinement skips did not make coverage incomplete: %+v", result.Coverage)
	}
	var output bytes.Buffer
	if err := Emit(&output, "symlink-confinement", result); err != nil {
		t.Fatal(err)
	}
	for lineNumber, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("invalid event line %d: %v", lineNumber+1, err)
		}
		if path, _ := event["path"].(string); path == "nested/go.mod" || path == "go.work" || path == "linked.go" {
			t.Fatalf("unsafe symlink path leaked into protocol event: %s", line)
		}
		if diagnostic, _ := event["diagnostic"].(map[string]any); diagnostic != nil {
			if path, _ := diagnostic["path"].(string); path == "nested/go.mod" || path == "go.work" || path == "linked.go" {
				t.Fatalf("unsafe symlink path leaked into diagnostic event: %s", line)
			}
		}
	}
}

func TestConditionCanonicalOrdering(t *testing.T) {
	condition, _, err := parseBuildCondition([]byte("//go:build z || (b && a)\n\npackage p\n"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(condition)
	if string(encoded) != `{"op":"any","conditions":[{"op":"all","conditions":[{"op":"defined","key":"go.build_tag:a"},{"op":"defined","key":"go.build_tag:b"}]},{"op":"defined","key":"go.build_tag:z"}]}` {
		t.Fatalf("unexpected canonical condition: %s", encoded)
	}
}

func TestBuildConditionFromFilename(t *testing.T) {
	condition, text, ok := buildConditionFromFilename("client_windows_amd64_test.go")
	if !ok || text != "amd64 && windows" || condition.Op != "all" || len(condition.Conditions) != 2 {
		t.Fatalf("unexpected filename condition: ok=%v text=%q condition=%+v", ok, text, condition)
	}
	if _, _, ok := buildConditionFromFilename("client_custom.go"); ok {
		t.Fatal("custom suffix must not be treated as an implicit platform constraint")
	}
}

func assertSiteStatus(t *testing.T, sites []Site, kind, specifier, status string) {
	t.Helper()
	for _, site := range sites {
		if site.Kind == kind && site.Specifier == specifier && site.ResolutionStatus == status {
			if len(site.TargetIDs) == 0 || len(site.Evidence) == 0 {
				t.Fatalf("site lacks target or evidence: %+v", site)
			}
			return
		}
	}
	t.Fatalf("missing %s site %q with status %s", kind, specifier, status)
}

func findSite(sites []Site, kind, specifier string) *Site {
	for index := range sites {
		if sites[index].Kind == kind && sites[index].Specifier == specifier {
			return &sites[index]
		}
	}
	return nil
}

func conditionDefines(condition Condition, key string) bool {
	if condition.Op == "defined" && condition.Key == key {
		return true
	}
	for _, child := range condition.Conditions {
		if conditionDefines(child, key) {
			return true
		}
	}
	return condition.Condition != nil && conditionDefines(*condition.Condition, key)
}

func conditionNegates(condition Condition, key string) bool {
	if condition.Op == "not" && condition.Condition != nil && conditionDefines(*condition.Condition, key) {
		return true
	}
	for _, child := range condition.Conditions {
		if conditionNegates(child, key) {
			return true
		}
	}
	return false
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("testdata", "workspace"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sortedStrings(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
