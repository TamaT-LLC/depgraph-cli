package worker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalysisUnitRequestRejectsUnsafeScopes(t *testing.T) {
	valid := AnalysisUnitRequest{
		ContractVersion: AnalysisUnitContractVersion,
		UnitID:          "analysis-unit:test",
		Adapter:         AdapterName,
		UnitRoot:        "module",
		SourcePaths:     []string{"module/main.go"},
		Stage:           AnalysisUnitStageSyntax,
	}
	tests := []struct {
		name   string
		mutate func(*AnalysisUnitRequest)
		want   string
	}{
		{name: "unsupported contract", mutate: func(request *AnalysisUnitRequest) { request.ContractVersion = "other" }, want: "contract version"},
		{name: "wrong adapter", mutate: func(request *AnalysisUnitRequest) { request.Adapter = "web" }, want: "adapter"},
		{name: "root escape", mutate: func(request *AnalysisUnitRequest) { request.UnitRoot = "../outside" }, want: "canonical repository-relative"},
		{name: "source escape", mutate: func(request *AnalysisUnitRequest) { request.SourcePaths = []string{"outside.go", "module/main.go"} }, want: "sorted"},
		{name: "source outside module", mutate: func(request *AnalysisUnitRequest) { request.SourcePaths = []string{"other/main.go"} }, want: "escapes unit_root"},
		{name: "duplicate source", mutate: func(request *AnalysisUnitRequest) { request.SourcePaths = []string{"module/main.go", "module/main.go"} }, want: "duplicate"},
		{name: "colon alias", mutate: func(request *AnalysisUnitRequest) { request.SourcePaths = []string{"module/drive:C.go"} }, want: "canonical repository-relative"},
		{name: "non Go source", mutate: func(request *AnalysisUnitRequest) { request.SourcePaths = []string{"module/readme.md"} }, want: "not a Go source"},
		{name: "invalid stage", mutate: func(request *AnalysisUnitRequest) { request.Stage = "ssa" }, want: "stage"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			err := request.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestReadAnalysisUnitRequestRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	root := t.TempDir()
	requestPath := filepath.Join(root, "request.json")
	valid := map[string]any{
		"contract_version": AnalysisUnitContractVersion,
		"unit_id":          "analysis-unit:test",
		"adapter":          AdapterName,
		"unit_root":        ".",
		"source_paths":     []string{"main.go"},
		"stage":            string(AnalysisUnitStageSyntax),
	}
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "unknown field", body: string(encoded[:len(encoded)-1]) + `,"extra":true}`},
		{name: "trailing data", body: string(encoded) + "\n{}\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(requestPath, []byte(test.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadAnalysisUnitRequest(requestPath); err == nil {
				t.Fatal("ReadAnalysisUnitRequest() unexpectedly accepted malformed input")
			}
		})
	}
}

func TestScanAnalysisUnitPreservesDuplicateModuleIdentityAndScope(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), "module example.com/duplicate\n\ngo 1.26.1\n\nrequire example.com/shared v1.0.0\n")
	writeTestFile(t, filepath.Join(root, "app", "main.go"), "package app\n\nimport _ \"example.com/shared\"\n")
	writeTestFile(t, filepath.Join(root, "other", "go.mod"), "module example.com/duplicate\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "other", "other.go"), "package other\n")
	writeTestFile(t, filepath.Join(root, "shared", "go.mod"), "module example.com/shared\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "shared", "shared.go"), "package shared\n")
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.26.1\n\nuse (\n\t./app\n\t./other\n\t./shared\n)\n")

	appRequest := AnalysisUnitRequest{
		ContractVersion: AnalysisUnitContractVersion,
		UnitID:          "analysis-unit:app",
		Adapter:         AdapterName,
		UnitRoot:        "app",
		SourcePaths:     []string{"app/main.go"},
		Stage:           AnalysisUnitStageSyntax,
	}
	otherRequest := appRequest
	otherRequest.UnitID = "analysis-unit:other"
	otherRequest.UnitRoot = "other"
	otherRequest.SourcePaths = []string{"other/other.go"}

	app, err := ScanWithAnalysisUnit(root, "", appRequest)
	if err != nil {
		t.Fatalf("ScanWithAnalysisUnit(app) error = %v", err)
	}
	other, err := ScanWithAnalysisUnit(root, "", otherRequest)
	if err != nil {
		t.Fatalf("ScanWithAnalysisUnit(other) error = %v", err)
	}
	if app.Profile.ID == other.Profile.ID {
		t.Fatalf("unit profiles collided: app=%s other=%s", app.Profile.ID, other.Profile.ID)
	}
	if app.Profile.Properties["analysis_stage"] != "syntax" || app.Profile.Properties["analysis_unit_root"] != "app" {
		t.Fatalf("app profile omitted analysis scope: %+v", app.Profile)
	}
	if !containsString(app.Coverage.Completeness, "syntax-complete") || containsString(app.Coverage.Completeness, "semantic-complete") {
		t.Fatalf("syntax unit advertised semantic completeness: %+v", app.Coverage)
	}
	if app.Coverage.FilesDiscovered != len(app.Files) {
		t.Fatalf("app unit discovery count included context files: coverage=%+v files=%d", app.Coverage, len(app.Files))
	}
	for _, file := range app.Files {
		if file.Path != "app/main.go" && file.Path != "app/go.mod" {
			t.Fatalf("app unit emitted out-of-scope file completion: %+v", file)
		}
	}
	if findSite(app.Sites, "side_effect_import", "example.com/shared") == nil {
		t.Fatalf("app unit lost local import site: %+v", app.Sites)
	}
	var appModule, otherModule Node
	for _, node := range app.Nodes {
		if node.Kind == "package_instance" && node.Properties["relative_dir"] == "app" {
			appModule = node
		}
		if node.Kind == "package_instance" && node.Properties["relative_dir"] == "other" {
			t.Fatalf("app unit emitted unrelated duplicate module: %+v", node)
		}
	}
	for _, node := range other.Nodes {
		if node.Kind == "package_instance" && node.Properties["relative_dir"] == "other" {
			otherModule = node
		}
	}
	if appModule.ID == "" || otherModule.ID == "" || appModule.ID == otherModule.ID {
		t.Fatalf("duplicate module instances did not retain identity: app=%+v other=%+v", appModule, otherModule)
	}

	appSemanticRequest := appRequest
	appSemanticRequest.Stage = AnalysisUnitStageSemantic
	sharedRequest := AnalysisUnitRequest{
		ContractVersion: AnalysisUnitContractVersion,
		UnitID:          "analysis-unit:shared",
		Adapter:         AdapterName,
		UnitRoot:        "shared",
		SourcePaths:     []string{"shared/shared.go"},
		Stage:           AnalysisUnitStageSyntax,
	}
	sharedSemanticRequest := sharedRequest
	sharedSemanticRequest.Stage = AnalysisUnitStageSemantic
	appSemantic, err := ScanWithAnalysisUnit(root, "", appSemanticRequest)
	if err != nil {
		t.Fatalf("ScanWithAnalysisUnit(app semantic) error = %v", err)
	}
	shared, err := ScanWithAnalysisUnit(root, "", sharedRequest)
	if err != nil {
		t.Fatalf("ScanWithAnalysisUnit(shared) error = %v", err)
	}
	sharedSemantic, err := ScanWithAnalysisUnit(root, "", sharedSemanticRequest)
	if err != nil {
		t.Fatalf("ScanWithAnalysisUnit(shared semantic) error = %v", err)
	}
	for _, result := range []Result{app, appSemantic, shared, sharedSemantic} {
		assertStableNodeAcrossUnitStages(t, result, "package_instance", "relative_dir", "shared")
		assertStableNodeAcrossUnitStages(t, result, "module", "package_path", "example.com/shared")
	}
	assertSameNodePayload(t, app, appSemantic, "package_instance", "relative_dir", "app")
	assertSameNodePayload(t, app, appSemantic, "file", "path", "app/main.go")
	assertSameNodePayload(t, app, shared, "package_instance", "relative_dir", "shared")
	assertSameNodePayload(t, app, shared, "module", "package_path", "example.com/shared")
	assertSameNodePayload(t, shared, sharedSemantic, "package_instance", "relative_dir", "shared")
	assertSameNodePayload(t, shared, sharedSemantic, "file", "path", "shared/shared.go")
}

func assertStableNodeAcrossUnitStages(t *testing.T, result Result, kind, property string, value string) {
	t.Helper()
	if node := findNodeProperty(result.Nodes, kind, property, value); node == nil || node.ID == "" {
		t.Fatalf("unit result omitted %s %s=%q target: %+v", kind, property, value, result.Nodes)
	}
}

func assertSameNodePayload(t *testing.T, left, right Result, kind, property, value string) {
	t.Helper()
	leftNode := findNodeProperty(left.Nodes, kind, property, value)
	rightNode := findNodeProperty(right.Nodes, kind, property, value)
	if leftNode == nil || rightNode == nil {
		t.Fatalf("missing %s %s=%q target: left=%+v right=%+v", kind, property, value, leftNode, rightNode)
	}
	if leftNode.ID != rightNode.ID {
		t.Fatalf("%s %s=%q ID changed across unit/stage: left=%q right=%q", kind, property, value, leftNode.ID, rightNode.ID)
	}
	leftJSON, err := json.Marshal(leftNode)
	if err != nil {
		t.Fatal(err)
	}
	rightJSON, err := json.Marshal(rightNode)
	if err != nil {
		t.Fatal(err)
	}
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("%s %s=%q payload conflict across unit/stage: left=%s right=%s", kind, property, value, leftJSON, rightJSON)
	}
}

func findNodeProperty(nodes []Node, kind, property, value string) *Node {
	for index := range nodes {
		if nodes[index].Kind != kind {
			continue
		}
		if got, ok := nodes[index].Properties[property].(string); ok && got == value {
			return &nodes[index]
		}
		if property == "path" && strings.TrimPrefix(nodes[index].Locator, "file:") == value {
			return &nodes[index]
		}
	}
	return nil
}

func TestScanAnalysisUnitPreservesLocalReplacementTarget(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), `module example.com/app

go 1.26.1

require example.com/replaced v1.0.0
replace example.com/replaced => ../replaced
`)
	writeTestFile(t, filepath.Join(root, "app", "main.go"), "package app\n\nimport _ \"example.com/replaced/pkg\"\n")
	writeTestFile(t, filepath.Join(root, "replaced", "go.mod"), "module example.com/replaced\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "replaced", "pkg", "pkg.go"), "package pkg\n")
	request := AnalysisUnitRequest{
		ContractVersion: AnalysisUnitContractVersion,
		UnitID:          "analysis-unit:replacement",
		Adapter:         AdapterName,
		UnitRoot:        "app",
		SourcePaths:     []string{"app/main.go"},
		Stage:           AnalysisUnitStageSyntax,
	}
	result, err := ScanWithAnalysisUnit(root, "", request)
	if err != nil {
		t.Fatalf("ScanWithAnalysisUnit() error = %v", err)
	}
	requirement := findSite(result.Sites, "module_requirement", "example.com/replaced")
	if requirement == nil || requirement.ResolutionStatus != "resolved" || len(requirement.TargetIDs) != 1 {
		t.Fatalf("local replacement requirement was not resolved: %+v", requirement)
	}
	var target Node
	for _, node := range result.Nodes {
		if node.ID == requirement.TargetIDs[0] {
			target = node
		}
	}
	if target.Kind != "package_instance" || target.Properties["relative_dir"] != "replaced" {
		t.Fatalf("local replacement target lost module instance identity: %+v", target)
	}
	importSite := findSite(result.Sites, "side_effect_import", "example.com/replaced/pkg")
	if importSite == nil || importSite.ResolutionStatus != "resolved" {
		t.Fatalf("local replacement import was not resolved: %+v", importSite)
	}
}

func TestScanAnalysisUnitSemanticStageDoesNotRepeatSourceGraph(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/semantic-unit\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package semantic\n\nimport \"fmt\"\n\nfunc Target() {}\nfunc Caller() { fmt.Sprint(1); Target() }\n")
	request := AnalysisUnitRequest{
		ContractVersion: AnalysisUnitContractVersion,
		UnitID:          "analysis-unit:semantic",
		Adapter:         AdapterName,
		UnitRoot:        ".",
		SourcePaths:     []string{"main.go"},
		Stage:           AnalysisUnitStageSemantic,
	}
	result, err := ScanWithAnalysisUnit(root, "", request)
	if err != nil {
		t.Fatalf("ScanWithAnalysisUnit() error = %v", err)
	}
	if result.Profile.Properties["analysis_stage"] != "semantic" {
		t.Fatalf("semantic profile omitted stage: %+v", result.Profile)
	}
	for _, edge := range result.Edges {
		if edge.Phase == "source" && edge.Kind != "contains" {
			t.Fatalf("semantic unit repeated source edge: %+v", edge)
		}
	}
	for _, site := range result.Sites {
		if len(site.Evidence) == 0 || site.Evidence[0].Kind != "semantic" {
			t.Fatalf("semantic unit repeated source site: %+v", site)
		}
	}
	for _, completion := range result.Files {
		switch completion.Path {
		case "go.mod":
			if completion.DiscoveredSites != 0 || completion.EmittedSites != 0 {
				t.Fatalf("semantic manifest ledger retained source counts: %+v", completion)
			}
		case "main.go":
			if completion.DiscoveredSites != len(result.Sites) || completion.EmittedSites != len(result.Sites) {
				t.Fatalf("semantic source ledger does not match retained sites: %+v sites=%d", completion, len(result.Sites))
			}
		}
	}
}

func TestScanAnalysisUnitSemanticStageScopesClosureEvidenceToOwnedSources(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), `module example.com/app

go 1.26.1

require example.com/shared v1.0.0
replace example.com/shared => ../shared
`)
	writeTestFile(t, filepath.Join(root, "app", "main.go"), `package app

import "example.com/shared"

func Use(value shared.Wrapper) shared.Value { return value.Value }
`)
	writeTestFile(t, filepath.Join(root, "shared", "go.mod"), "module example.com/shared\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "shared", "types.go"), `package shared

type Value struct { Number int }
type Wrapper struct { Value Value }
`)
	request := AnalysisUnitRequest{
		ContractVersion: AnalysisUnitContractVersion,
		UnitID:          "analysis-unit:closure-scope",
		Adapter:         AdapterName,
		UnitRoot:        "app",
		SourcePaths:     []string{"app/main.go"},
		Stage:           AnalysisUnitStageSemantic,
	}
	result, err := ScanWithAnalysisUnit(root, "", request)
	if err != nil {
		t.Fatalf("ScanWithAnalysisUnit() error = %v", err)
	}
	for _, site := range result.Sites {
		if len(site.Evidence) == 0 || site.Evidence[0].Path != "app/main.go" {
			t.Fatalf("semantic site escaped the owned source scope: %+v", site)
		}
	}
	for _, edge := range result.Edges {
		if edge.Phase != "semantic" {
			continue
		}
		for _, evidence := range edge.Evidence {
			if evidence.Path != "app/main.go" {
				t.Fatalf("semantic edge escaped the owned source scope: %+v", edge)
			}
		}
	}
	if findNodeProperty(result.Nodes, "module", "package_path", "example.com/shared") == nil {
		t.Fatal("semantic closure dropped the shared target package node")
	}
}

func TestScanAnalysisUnitAssemblyOwnershipUsesNearestModule(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), "module example.com/app\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "app", "limits.go"), "package app\n\nfunc assemblyEntry()\n")
	writeTestFile(t, filepath.Join(root, "app", "bridge.s"), "TEXT ·bridge(SB),$0-0\n\tRET\n")
	writeTestFile(t, filepath.Join(root, "app", "upper.S"), "TEXT ·upper(SB),$0-0\n\tRET\n")
	writeTestFile(t, filepath.Join(root, "app", "nested", "go.mod"), "module example.com/nested\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "app", "nested", "nested.s"), "TEXT ·nested(SB),$0-0\n\tRET\n")

	request := AnalysisUnitRequest{
		ContractVersion: AnalysisUnitContractVersion,
		UnitID:          "analysis-unit:assembly-ownership",
		Adapter:         AdapterName,
		UnitRoot:        "app",
		SourcePaths:     []string{"app/limits.go"},
		Stage:           AnalysisUnitStageSyntax,
	}
	result, err := ScanWithAnalysisUnit(root, "", request)
	if err != nil {
		t.Fatalf("ScanWithAnalysisUnit() error = %v", err)
	}

	for _, path := range []string{"app/bridge.s", "app/upper.S"} {
		foundFile := false
		for _, file := range result.Files {
			if file.Path != path {
				continue
			}
			foundFile = true
			if file.DiscoveredSites != 1 || file.EmittedSites != 1 || file.Skipped {
				t.Fatalf("assembly file completion = %+v, want one emitted site", file)
			}
		}
		if !foundFile {
			t.Fatalf("owned assembly file %q was not completed: %+v", path, result.Files)
		}
		foundNode := false
		for _, node := range result.Nodes {
			if node.Kind == "file" && node.Locator == "file:"+path {
				foundNode = true
			}
		}
		if !foundNode {
			t.Fatalf("owned assembly file node %q was not emitted", path)
		}
		implementation := false
		for _, site := range result.Sites {
			if site.Kind != "callgraph_boundary" || len(site.Evidence) == 0 || site.Evidence[0].Path != path {
				continue
			}
			boundary, _ := site.Evidence[0].Properties["callgraph_boundary"].(string)
			if boundary != "assembly_implementation" {
				continue
			}
			implementation = true
			if diagnostic := callGraphLimitDiagnosticForSite(result.Diagnostics, site.ID); diagnostic == nil || diagnostic.Path != path {
				t.Fatalf("assembly boundary diagnostic for %q is missing or out of scope: site=%+v diagnostics=%+v", path, site, result.Diagnostics)
			}
		}
		if !implementation {
			t.Fatalf("assembly implementation site for %q was not emitted: %+v", path, result.Sites)
		}
	}
	for _, file := range result.Files {
		if strings.HasPrefix(file.Path, "app/nested/") {
			t.Fatalf("nested module assembly escaped the app unit: %+v", file)
		}
	}
	for _, node := range result.Nodes {
		if node.Kind == "file" && strings.HasPrefix(node.Locator, "file:app/nested/") {
			t.Fatalf("nested module assembly node escaped the app unit: %+v", node)
		}
	}
}

func TestScanAnalysisUnitSemanticStageDropsDiagnosticsForRemovedSourceSites(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), "module example.com/app\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "app", "limits.go"), "package app\n\nimport _ \"unsafe\"\n\nfunc assemblyEntry()\n")
	writeTestFile(t, filepath.Join(root, "app", "bridge.s"), "TEXT ·bridge(SB),$0-0\n\tRET\n")
	request := AnalysisUnitRequest{
		ContractVersion: AnalysisUnitContractVersion,
		UnitID:          "analysis-unit:semantic-boundaries",
		Adapter:         AdapterName,
		UnitRoot:        "app",
		SourcePaths:     []string{"app/limits.go"},
		Stage:           AnalysisUnitStageSemantic,
	}
	result, err := ScanWithAnalysisUnit(root, "", request)
	if err != nil {
		t.Fatalf("ScanWithAnalysisUnit() error = %v", err)
	}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code != "go_callgraph_limit" {
			continue
		}
		t.Fatalf("semantic stage retained diagnostic for a removed source site: %+v", diagnostic)
	}
}

func callGraphLimitDiagnosticForSite(diagnostics []Diagnostic, siteID string) *Diagnostic {
	for index := range diagnostics {
		diagnostic := &diagnostics[index]
		if diagnostic.Code != "go_callgraph_limit" {
			continue
		}
		if candidate, ok := diagnostic.Properties["site_id"].(string); ok && candidate == siteID {
			return diagnostic
		}
	}
	return nil
}
