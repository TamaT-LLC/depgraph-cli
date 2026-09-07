package worker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func validSplitBinding() *AnalysisSplitBinding {
	return &AnalysisSplitBinding{
		ContractVersion: AnalysisSplitContractVersion,
		SplitPlanID:     "analysis-split-plan:test",
		ExecutionUnitID: "analysis-execution-unit:test",
		SplitKind:       "input_batch",
		Loader: AnalysisLoaderBinding{
			Kind:           "files",
			Paths:          []string{"app/a.go"},
			PackageRoots:   []string{"app"},
			ReferenceDepth: "paths_only",
			ReferencePaths: []string{"app/b.go", "shared/shared.go"},
			InputSplit:     true,
		},
	}
}

func TestAnalysisSplitBindingValidatesLoaderScopeAgainstOwnership(t *testing.T) {
	valid := AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:split",
		Adapter:            AdapterName,
		UnitRoot:           "app",
		SourcePaths:        []string{"app/a.go"},
		Stage:              AnalysisUnitStageSyntax,
		ContextPaths:       []string{"app/a.go", "app/b.go", "shared/shared.go"},
		ChunkID:            "chunk-0",
		ChunkIndex:         0,
		ChunkCount:         2,
		ContextFingerprint: "context-sha256:split",
		Split:              validSplitBinding(),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid split binding rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*AnalysisUnitRequest)
		want   string
	}{
		{name: "contract", mutate: func(request *AnalysisUnitRequest) {
			request.Split.ContractVersion = "depgraph-analysis-split-plan-v0"
		}, want: "split contract version"},
		{name: "plan id", mutate: func(request *AnalysisUnitRequest) {
			request.Split.SplitPlanID = ""
		}, want: "split_plan_id"},
		{name: "execution unit id", mutate: func(request *AnalysisUnitRequest) {
			request.Split.ExecutionUnitID = strings.Repeat("x", 4097)
		}, want: "execution_unit_id"},
		{name: "split kind", mutate: func(request *AnalysisUnitRequest) {
			request.Split.SplitKind = "partial"
		}, want: "split_kind"},
		{name: "loader kind", mutate: func(request *AnalysisUnitRequest) {
			request.Split.Loader.Kind = "workspace"
		}, want: "loader kind"},
		{name: "reference depth", mutate: func(request *AnalysisUnitRequest) {
			request.Split.Loader.ReferenceDepth = "everything"
		}, want: "reference_depth"},
		{name: "loader paths sorted", mutate: func(request *AnalysisUnitRequest) {
			request.Split.Loader.Paths = []string{"app/b.go", "app/a.go"}
			request.Split.Loader.ReferencePaths = []string{"shared/shared.go"}
		}, want: "split.loader.paths must be sorted"},
		{name: "loader path escapes", mutate: func(request *AnalysisUnitRequest) {
			request.Split.Loader.Paths = []string{"../outside/a.go", "app/a.go"}
		}, want: "canonical repository-relative"},
		{name: "loader path not Go", mutate: func(request *AnalysisUnitRequest) {
			request.Split.Loader.Paths = []string{"app/a.go", "app/notes.md"}
		}, want: "not a Go source"},
		{name: "ownership outside loader", mutate: func(request *AnalysisUnitRequest) {
			request.Split.Loader.Paths = []string{"app/c.go"}
		}, want: "not included in split.loader.paths"},
		{name: "reference overlaps loader", mutate: func(request *AnalysisUnitRequest) {
			request.Split.Loader.ReferencePaths = []string{"app/a.go", "shared/shared.go"}
		}, want: "also a loader path"},
		{name: "package roots sorted", mutate: func(request *AnalysisUnitRequest) {
			request.Split.Loader.PackageRoots = []string{"shared", "app"}
		}, want: "split.loader.package_roots must be sorted"},
		{name: "output-only split posing as input split", mutate: func(request *AnalysisUnitRequest) {
			request.Split.Loader.ReferencePaths = nil
		}, want: "input_split does not match"},
		{name: "input split without references", mutate: func(request *AnalysisUnitRequest) {
			request.Split.Loader.InputSplit = false
		}, want: "input_split does not match"},
		{name: "whole with several chunks", mutate: func(request *AnalysisUnitRequest) {
			request.Split.SplitKind = "whole"
		}, want: "requires a single chunk"},
		{name: "batch with one chunk", mutate: func(request *AnalysisUnitRequest) {
			request.ChunkCount = 1
		}, want: "requires more than one chunk"},
		{name: "legacy contract", mutate: func(request *AnalysisUnitRequest) {
			request.ContractVersion = LegacyAnalysisUnitContractVersion
			request.ContextPaths = nil
			request.ChunkCount = 0
		}, want: "split requires " + AnalysisUnitContractVersion},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			binding := *validSplitBinding()
			request.Split = &binding
			test.mutate(&request)
			if err := request.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestReadAnalysisUnitRequestAcceptsSplitBindingAndStaysStrict(t *testing.T) {
	root := t.TempDir()
	requestPath := filepath.Join(root, "request.json")
	request := map[string]any{
		"contract_version":    AnalysisUnitContractVersion,
		"unit_id":             "analysis-unit:split",
		"adapter":             AdapterName,
		"unit_root":           "app",
		"source_paths":        []string{"app/a.go"},
		"stage":               string(AnalysisUnitStageSyntax),
		"context_paths":       []string{"app/a.go", "app/b.go"},
		"chunk_id":            "chunk-0",
		"chunk_index":         0,
		"chunk_count":         2,
		"auxiliary_paths":     []string{},
		"context_fingerprint": "context-sha256:split",
		"split": map[string]any{
			"contract_version":  AnalysisSplitContractVersion,
			"split_plan_id":     "analysis-split-plan:test",
			"execution_unit_id": "analysis-execution-unit:test",
			"split_kind":        "input_batch",
			"loader": map[string]any{
				"kind":            "files",
				"paths":           []string{"app/a.go"},
				"package_roots":   []string{"app"},
				"reference_depth": "paths_only",
				"reference_paths": []string{"app/b.go"},
				"input_split":     true,
			},
		},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(requestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadAnalysisUnitRequest(requestPath)
	if err != nil {
		t.Fatalf("ReadAnalysisUnitRequest() rejected a valid split binding: %v", err)
	}
	if decoded.Split == nil || decoded.Split.ExecutionUnitID != "analysis-execution-unit:test" || !decoded.Split.Loader.InputSplit {
		t.Fatalf("split binding was not decoded: %+v", decoded.Split)
	}
	// The binding stays closed: the core adds fields only through a new
	// contract version, so unknown loader fields must still fail the request.
	strict := strings.Replace(string(encoded), `"input_split":true`, `"input_split":true,"estimate":{}`, 1)
	if strict == string(encoded) {
		t.Fatal("test setup did not inject the unknown field")
	}
	if err := os.WriteFile(requestPath, []byte(strict), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAnalysisUnitRequest(requestPath); err == nil {
		t.Fatal("ReadAnalysisUnitRequest() accepted an unknown split loader field")
	}
}

func TestAnalysisSplitBindingIsEchoedWithoutChangingResultsOrIdentity(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), "module example.com/app\n\ngo 1.26.1\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ../dep\n")
	writeTestFile(t, filepath.Join(root, "app", "a.go"), "package app\n\nimport dep \"example.com/dep\"\n\nfunc A() int { return dep.Value() }\n")
	writeTestFile(t, filepath.Join(root, "app", "b.go"), "package app\n\nfunc B() int { return A() }\n")
	writeTestFile(t, filepath.Join(root, "dep", "go.mod"), "module example.com/dep\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "dep", "dep.go"), "package dep\n\nfunc Value() int { return 1 }\n")

	syntax := AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:split-echo",
		Adapter:            AdapterName,
		UnitRoot:           "app",
		SourcePaths:        []string{"app/a.go"},
		Stage:              AnalysisUnitStageSyntax,
		ContextPaths:       []string{"app/a.go", "app/b.go", "dep/dep.go"},
		ChunkID:            "chunk-0",
		ChunkIndex:         0,
		ChunkCount:         2,
		AuxiliaryPaths:     []string{"app/go.mod"},
		ContextFingerprint: "context-sha256:split-echo",
	}
	bound := syntax
	bound.Split = &AnalysisSplitBinding{
		ContractVersion: AnalysisSplitContractVersion,
		SplitPlanID:     "analysis-split-plan:echo",
		ExecutionUnitID: "analysis-execution-unit:echo-syntax",
		SplitKind:       "input_batch",
		Loader: AnalysisLoaderBinding{
			Kind:           "files",
			Paths:          []string{"app/a.go"},
			PackageRoots:   []string{"app"},
			ReferenceDepth: "paths_only",
			ReferencePaths: []string{"app/b.go", "dep/dep.go"},
			InputSplit:     true,
		},
	}
	plain, err := ScanWithAnalysisUnit(root, "", syntax)
	if err != nil {
		t.Fatalf("plain syntax request failed: %v", err)
	}
	echoed, err := ScanWithAnalysisUnit(root, "", bound)
	if err != nil {
		t.Fatalf("bound syntax request failed: %v", err)
	}
	for key, want := range map[string]string{
		"analysis_split_contract":     AnalysisSplitContractVersion,
		"analysis_split_plan_id":      "analysis-split-plan:echo",
		"analysis_execution_unit_id":  "analysis-execution-unit:echo-syntax",
		"analysis_split_kind":         "input_batch",
		"analysis_loader_kind":        "files",
		"analysis_loader_input_split": "true",
		"analysis_loader_scope":       AnalysisLoaderScopeApplied,
	} {
		if got := echoed.Profile.Properties[key]; got != want {
			t.Fatalf("profile property %s = %q, want %q", key, got, want)
		}
	}
	if _, present := plain.Profile.Properties["analysis_split_plan_id"]; present {
		t.Fatal("request without a split binding echoed split properties")
	}
	if plain.Profile.ID != echoed.Profile.ID {
		t.Fatalf("split binding changed the profile identity: %s vs %s", plain.Profile.ID, echoed.Profile.ID)
	}
	plainNodes, err := json.Marshal(sortedNodes(plain.Nodes))
	if err != nil {
		t.Fatal(err)
	}
	echoedNodes, err := json.Marshal(sortedNodes(echoed.Nodes))
	if err != nil {
		t.Fatal(err)
	}
	if string(plainNodes) != string(echoedNodes) {
		t.Fatalf("split binding changed emitted nodes:\n%s\n%s", plainNodes, echoedNodes)
	}
	if len(plain.Files) != len(echoed.Files) {
		t.Fatalf("split binding changed the file ledger: %d vs %d", len(plain.Files), len(echoed.Files))
	}

	// A typed request bound to a package loader is honoured by loading the
	// complete module, and the worker says so instead of claiming the bound.
	typed := AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:split-echo",
		Adapter:            AdapterName,
		UnitRoot:           "app",
		SourcePaths:        []string{"app/a.go", "app/b.go"},
		Stage:              AnalysisUnitStageTyped,
		ContextPaths:       []string{"app/a.go", "app/b.go"},
		ChunkID:            "chunk-typed",
		ChunkIndex:         0,
		ChunkCount:         1,
		ContextFingerprint: "context-sha256:split-echo",
		Split: &AnalysisSplitBinding{
			ContractVersion: AnalysisSplitContractVersion,
			SplitPlanID:     "analysis-split-plan:echo",
			ExecutionUnitID: "analysis-execution-unit:echo-typed",
			SplitKind:       "whole",
			Loader: AnalysisLoaderBinding{
				Kind:           "package",
				Paths:          []string{"app/a.go", "app/b.go"},
				PackageRoots:   []string{"app"},
				ReferenceDepth: "declarations",
				ReferencePaths: []string{"dep/dep.go"},
				InputSplit:     true,
			},
		},
	}
	widened, err := ScanWithAnalysisUnit(root, "", typed)
	if err != nil {
		t.Fatalf("typed request with a package binding failed: %v", err)
	}
	if got := widened.Profile.Properties["analysis_loader_scope"]; got != AnalysisLoaderScopeWidened {
		t.Fatalf("analysis_loader_scope = %q, want %q", got, AnalysisLoaderScopeWidened)
	}
	if got := widened.Profile.Properties["go_typed_stage_complete"]; got != "true" {
		t.Fatalf("typed stage did not complete with the split binding present: %q", got)
	}
	typed.Split.Loader.Kind = "module"
	typed.Split.Loader.Paths = []string{"app/a.go", "app/b.go", "dep/dep.go"}
	typed.Split.Loader.PackageRoots = []string{"app", "dep"}
	typed.Split.Loader.ReferenceDepth = "bodies"
	typed.Split.Loader.ReferencePaths = nil
	typed.Split.Loader.InputSplit = false
	applied, err := ScanWithAnalysisUnit(root, "", typed)
	if err != nil {
		t.Fatalf("typed request with a module binding failed: %v", err)
	}
	if got := applied.Profile.Properties["analysis_loader_scope"]; got != AnalysisLoaderScopeApplied {
		t.Fatalf("analysis_loader_scope = %q, want %q", got, AnalysisLoaderScopeApplied)
	}
}

func sortedNodes(nodes []Node) []Node {
	sorted := append([]Node(nil), nodes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	return sorted
}
