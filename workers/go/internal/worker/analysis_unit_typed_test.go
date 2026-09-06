package worker

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestScanAnalysisUnitTypedStageEmitsCompleteTypePrefixWithoutSSA(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root+"/go.mod", "module example.com/typed-stage\n\ngo 1.26.1\n")
	writeTestFile(t, root+"/main.go", `package typed

type Runner interface {
	Run() string
}

type runner struct{}

func (runner) Run() string { return "ok" }

func Invoke(value Runner) string { return value.Run() }
`)
	request := AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:typed",
		Adapter:            AdapterName,
		UnitRoot:           ".",
		SourcePaths:        []string{"main.go"},
		Stage:              AnalysisUnitStageTyped,
		ContextPaths:       []string{"main.go"},
		ChunkID:            "typed",
		ChunkIndex:         0,
		ChunkCount:         1,
		ContextFingerprint: "context-sha256:typed",
	}
	var progress []string
	result, err := ScanWithAnalysisUnitProgress(root, "", request, func(phase, status string, items int) {
		progress = append(progress, phase+"/"+status+"/"+itoa(items))
	})
	if err != nil {
		t.Fatalf("typed analysis unit failed: %v", err)
	}
	if got := result.Profile.Properties["analysis_stage"]; got != string(AnalysisUnitStageTyped) {
		t.Fatalf("analysis stage = %q, want typed: %+v", got, result.Profile.Properties)
	}
	if got := result.Profile.Properties["analysis_scope"]; got != "full_module" {
		t.Fatalf("typed analysis scope = %q, want full_module", got)
	}
	if got := result.Profile.Properties["go_typed_stage_complete"]; got != "true" {
		t.Fatalf("typed completion property = %q, want true: %+v", got, result.Profile.Properties)
	}
	if !containsString(result.Coverage.Completeness, "syntax-complete") || containsString(result.Coverage.Completeness, "semantic-complete") {
		t.Fatalf("typed stage advertised invalid completeness: %+v", result.Coverage)
	}
	if len(result.Coverage.Completeness) != 1 {
		t.Fatalf("typed stage completeness = %v, want syntax-complete only", result.Coverage.Completeness)
	}
	if !containsProgress(progress, "go_typed_load", "progress") || !containsProgress(progress, "go_typed_load", "completed") {
		t.Fatalf("typed load progress was not reported: %v", progress)
	}
	if containsProgressPhase(progress, "go_ssa") {
		t.Fatalf("typed stage invoked SSA progress: %v", progress)
	}
	if !hasTypedStageEdge(result.Edges, "implements") {
		t.Fatalf("typed stage omitted type-only implements relation: %+v", result.Edges)
	}
	if !hasTypedStageSite(result.Sites, "type_use") {
		t.Fatalf("typed stage omitted type-use relation: %+v", result.Sites)
	}
	for _, diagnostic := range result.Diagnostics {
		if strings.HasPrefix(diagnostic.Code, "go_ssa") {
			t.Fatalf("typed stage emitted SSA diagnostic: %+v", diagnostic)
		}
	}

	var encoded bytes.Buffer
	if err := Emit(&encoded, "typed-scan", result); err != nil {
		t.Fatalf("typed protocol emission failed: %v", err)
	}
	events := decodeTypedProtocol(t, encoded.Bytes())
	if events[0]["event"] != "scan_started" || events[len(events)-1]["event"] != "scan_completed" {
		t.Fatalf("typed stream is not a complete protocol stream: first=%v last=%v", events[0]["event"], events[len(events)-1]["event"])
	}
	profileEvent := findTypedEvent(events, "profile_declared")
	profile, ok := profileEvent["profile"].(map[string]any)
	if !ok {
		t.Fatalf("typed profile event has invalid payload: %+v", profileEvent)
	}
	properties, ok := profile["properties"].(map[string]any)
	if !ok || properties["go_typed_stage_complete"] != "true" {
		t.Fatalf("typed profile omitted completion property: %+v", profileEvent)
	}
	coverageEvent := findTypedEvent(events, "scan_completed")
	coverage, ok := coverageEvent["coverage"].(map[string]any)
	if !ok {
		t.Fatalf("typed scan completion has invalid coverage: %+v", coverageEvent)
	}
	completeness, ok := coverage["completeness"].([]any)
	if !ok || len(completeness) != 1 || completeness[0] != "syntax-complete" {
		t.Fatalf("typed stream completion = %v, want syntax-complete only", coverage["completeness"])
	}
}

func TestScanAnalysisUnitTypedStageMarksIncompleteLoadWithoutSemanticCompleteness(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root+"/go.mod", `module example.com/typed-incomplete

go 1.26.1

require example.invalid/missing v1.0.0
`)
	writeTestFile(t, root+"/main.go", `package incomplete

import _ "example.invalid/missing/pkg"
`)
	request := AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:typed-incomplete",
		Adapter:            AdapterName,
		UnitRoot:           ".",
		SourcePaths:        []string{"main.go"},
		Stage:              AnalysisUnitStageTyped,
		ContextPaths:       []string{"main.go"},
		ChunkID:            "typed",
		ChunkIndex:         0,
		ChunkCount:         1,
		ContextFingerprint: "context-sha256:typed-incomplete",
	}
	result, err := ScanWithAnalysisUnit(root, "", request)
	if err != nil {
		t.Fatalf("incomplete typed analysis unit failed instead of returning a result: %v", err)
	}
	if got := result.Profile.Properties["go_typed_stage_complete"]; got != "false" {
		t.Fatalf("incomplete typed completion property = %q, want false: %+v", got, result.Profile.Properties)
	}
	if containsString(result.Coverage.Completeness, "semantic-complete") {
		t.Fatalf("incomplete typed stage advertised semantic completeness: %+v", result.Coverage)
	}
	if !containsString(result.Coverage.Reasons, "go-typed-incomplete") {
		t.Fatalf("incomplete typed reason missing: %+v", result.Coverage)
	}
	if !hasDiagnostic(result.Diagnostics, "go_packages_load_failed") && !hasDiagnostic(result.Diagnostics, "go_packages_package_error") && !hasDiagnostic(result.Diagnostics, "go_packages_module_fallback") {
		t.Fatalf("incomplete typed load lacked a diagnostic: %+v", result.Diagnostics)
	}

	var encoded bytes.Buffer
	if err := Emit(&encoded, "typed-incomplete", result); err != nil {
		t.Fatalf("incomplete typed protocol emission failed: %v", err)
	}
	events := decodeTypedProtocol(t, encoded.Bytes())
	if events[0]["event"] != "scan_started" || events[len(events)-1]["event"] != "scan_completed" {
		t.Fatalf("incomplete typed stream is not complete: first=%v last=%v", events[0]["event"], events[len(events)-1]["event"])
	}
}

func TestAnalysisUnitTypedStageRequiresOneChunkAndV2Contract(t *testing.T) {
	request := AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:typed-validation",
		Adapter:            AdapterName,
		UnitRoot:           ".",
		SourcePaths:        []string{"main.go"},
		Stage:              AnalysisUnitStageTyped,
		ContextPaths:       []string{"main.go"},
		ChunkID:            "typed",
		ChunkCount:         2,
		ContextFingerprint: "context-sha256:typed-validation",
	}
	if err := request.Validate(); err == nil || !strings.Contains(err.Error(), "exactly one chunk") {
		t.Fatalf("typed request with two chunks was accepted: %v", err)
	}
	request.ChunkCount = 1
	request.ContextPaths = []string{"main.go", "other.go"}
	if err := request.Validate(); err == nil || !strings.Contains(err.Error(), "complete context_paths") {
		t.Fatalf("typed request with a partial source scope was accepted: %v", err)
	}
	request.ContextPaths = []string{"main.go"}
	request.ContractVersion = LegacyAnalysisUnitContractVersion
	if err := request.Validate(); err == nil || !strings.Contains(err.Error(), AnalysisUnitContractVersion) {
		t.Fatalf("legacy typed request was accepted: %v", err)
	}
}

func containsProgress(progress []string, phase, status string) bool {
	prefix := phase + "/" + status + "/"
	for _, item := range progress {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}

func containsProgressPhase(progress []string, phase string) bool {
	prefix := phase + "/"
	for _, item := range progress {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}

func hasTypedStageEdge(edges []Edge, kind string) bool {
	for _, edge := range edges {
		if edge.Kind == kind && edge.Phase == "semantic" {
			return true
		}
	}
	return false
}

func hasTypedStageSite(sites []Site, kind string) bool {
	for _, site := range sites {
		if site.Kind == kind && len(site.Evidence) > 0 && site.Evidence[0].Kind == "semantic" {
			return true
		}
	}
	return false
}

func decodeTypedProtocol(t *testing.T, encoded []byte) []map[string]any {
	t.Helper()
	scanner := bufio.NewScanner(bytes.NewReader(encoded))
	events := make([]map[string]any, 0)
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("typed stream contains invalid JSON: %v", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read typed stream: %v", err)
	}
	if len(events) < 3 {
		t.Fatalf("typed stream is unexpectedly short: %v", events)
	}
	return events
}

func findTypedEvent(events []map[string]any, name string) map[string]any {
	for _, event := range events {
		if event["event"] == name {
			return event
		}
	}
	return nil
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
