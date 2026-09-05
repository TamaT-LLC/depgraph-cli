package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/TamaT-LLC/depgraph-cli/workers/go/internal/worker"
)

func TestRunEndToEnd(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal", "worker", "testdata", "workspace"))
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"--root", root, "--scan-id", "integration"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() code = %d, stderr=%s", code, stderr.String())
	}
	if stdout.Len() == 0 || stderr.Len() == 0 {
		t.Fatalf("expected protocol on stdout and logs on stderr; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("stdout contained non-protocol content: %q (%v)", scanner.Text(), err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestRunUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("run() code = %d; want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("usage error polluted stdout: %q", stdout.String())
	}
}

func TestRunVersionAdvertisesAnalysisUnitCapability(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, stderr=%s", code, stderr.String())
	}
	if got, want := stdout.String(), "depgraph-go-worker 0.6.0 (protocol 1.0; capabilities analysis-go-package-loader-v1,analysis-loader-scope-v1,analysis-source-batch-v1,analysis-unit-typed-v1)\n"; got != want {
		t.Fatalf("version handshake = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("version handshake polluted stderr: %q", stderr.String())
	}
}

func TestRunAnalysisUnitEmitsBoundedStageProgress(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/progress\n\ngo 1.26.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package progress\n\nfunc Target() {}\nfunc Caller() { Target() }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(root, "request.json")
	request := worker.AnalysisUnitRequest{
		ContractVersion:    worker.AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:progress",
		Adapter:            worker.AdapterName,
		UnitRoot:           ".",
		SourcePaths:        []string{"main.go"},
		Stage:              worker.AnalysisUnitStageSemantic,
		ContextPaths:       []string{"main.go"},
		ChunkID:            "semantic",
		ChunkCount:         1,
		ContextFingerprint: "progress-context",
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(requestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--root", root, "--scan-id", "progress", "--analysis-unit", requestPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, stderr=%s", code, stderr.String())
	}
	logs := stderr.String()
	for _, want := range []string{
		"depgraph-progress phase=go_syntax status=progress items=0",
		"depgraph-progress phase=go_syntax status=progress items=1",
		"depgraph-progress phase=go_syntax status=completed items=1",
		"depgraph-progress phase=go_typed_load status=progress items=0",
		"depgraph-progress phase=go_typed_load status=completed items=",
		"depgraph-progress phase=go_ssa status=progress items=0",
		"depgraph-progress phase=go_ssa status=completed items=",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("stderr omitted progress boundary %q: %s", want, logs)
		}
	}
	if stdout.Len() == 0 {
		t.Fatal("analysis-unit run emitted no protocol output")
	}
}

func TestRunRejectsAnalysisUnitRootEscapeWithFailureStream(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/invalid\n\ngo 1.26.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(root, "request.json")
	request := `{"contract_version":"depgraph-analysis-unit-v1","unit_id":"analysis-unit:invalid","adapter":"go","unit_root":"../outside","source_paths":[],"stage":"syntax"}`
	if err := os.WriteFile(requestPath, []byte(request), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--root", root, "--scan-id", "invalid", "--analysis-unit", requestPath}, &stdout, &stderr); code != 3 {
		t.Fatalf("run() code = %d, want 3; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "canonical repository-relative") {
		t.Fatalf("root escape was not reported on stderr: %s", stderr.String())
	}
	var events []map[string]any
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("failure output contained non-protocol content: %q (%v)", scanner.Text(), err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0]["event"] != "scan_started" || events[1]["event"] != "diagnostic" || events[2]["event"] != "scan_completed" {
		t.Fatalf("invalid request failure stream = %+v", events)
	}
}

func TestRunMovesToNeutralDirectoryBeforeToolLookup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell marker fixture is Unix-only")
	}
	root := t.TempDir()
	marker := filepath.Join(root, "project-go-was-run")
	for path, content := range map[string]string{
		filepath.Join(root, "go.mod"):  "module example.com/neutral\n\ngo 1.26.1\n",
		filepath.Join(root, "main.go"): "package neutral\n",
		filepath.Join(root, "go"):      "#!/bin/sh\ntouch '" + strings.ReplaceAll(marker, "'", "'\"'\"'") + "'\nexit 99\n",
	} {
		mode := os.FileMode(0o644)
		if filepath.Base(path) == "go" {
			mode = 0o755
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(root)
	t.Setenv("PATH", "."+string(os.PathListSeparator)+os.Getenv("PATH"))
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"--root", ".", "--scan-id", "neutral"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("project-local go command was executed: %v", err)
	}
	current, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if current != previous {
		t.Fatalf("run() restored cwd to %q; want %q", current, previous)
	}
}

func TestRunIssue437HealthFixtureEmitsRealSemanticGraph(t *testing.T) {
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the command package")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", "..", "internal", "worker", "testdata", "health"))

	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"--root", root, "--scan-id", "issue437-health-e2e"}, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("run() exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", "..", "..", ".."))
	fixturePath := filepath.Join(repoRoot, "crates", "depgraph-core", "tests", "fixtures", "health", "issue437-go.ndjson")
	fixtureBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read Go health fixture %s: %v", fixturePath, err)
	}
	// This assertion exercises the real command envelope path. The worker
	// package test covers Scan/Emit directly; this one ensures run() forwards
	// the complete golden graph and completion ledger unchanged.
	issue437AssertRunGolden(t, stdout.Bytes(), fixtureBytes)

	wantResolvers := map[string]string{
		"example.com/issue437/cmd.main":         "main",
		"example.com/issue437/pkg.Caller":       "Caller",
		"example.com/issue437/pkg.UsedExport":   "UsedExport",
		"example.com/issue437/pkg.UnusedExport": "UnusedExport",
		"example.com/issue437/pkg.UsedType":     "UsedType",
		"example.com/issue437/pkg.UnusedType":   "UnusedType",
	}
	seenResolvers := map[string]bool{}
	seenCompleted := false
	scanner := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
	line := 0
	for scanner.Scan() {
		line++
		var event struct {
			Event               string           `json:"event"`
			Seq                 uint64           `json:"seq"`
			Node                *worker.Node     `json:"node"`
			ProjectCodeExecuted *bool            `json:"project_code_executed"`
			Coverage            *worker.Coverage `json:"coverage"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("line %d is not JSON: %v", line, err)
		}
		if event.Seq != uint64(line) {
			t.Fatalf("line %d has seq %d", line, event.Seq)
		}
		switch event.Event {
		case "scan_started":
			if event.ProjectCodeExecuted == nil || *event.ProjectCodeExecuted {
				t.Fatalf("scan_started reported project code execution")
			}
		case "node_upsert":
			if event.Node == nil || (event.Node.Kind != "symbol" && event.Node.Kind != "type") {
				continue
			}
			identity, ok := event.Node.Properties["canonical_identity"].(map[string]any)
			if !ok {
				t.Fatalf("semantic node %s has no canonical identity", event.Node.ID)
			}
			resolver, ok := identity["resolver_identity"].(string)
			if !ok || wantResolvers[resolver] == "" {
				t.Fatalf("unexpected semantic resolver %q in node %+v", resolver, event.Node)
			}
			if event.Node.DisplayName != wantResolvers[resolver] {
				t.Fatalf("resolver %q display name = %q, want %q", resolver, event.Node.DisplayName, wantResolvers[resolver])
			}
			seenResolvers[resolver] = true
			for property := range event.Node.Properties {
				if property != "canonical_identity" && property != "language" && property != "package_locator" && property != "symbol_kind" && property != "type_kind" {
					t.Fatalf("worker emitted synthetic semantic property %q on %q", property, resolver)
				}
			}
		case "scan_completed":
			seenCompleted = true
			if event.Coverage == nil || event.Coverage.ProjectCodeExecuted || !contains(event.Coverage.Completeness, "semantic-complete") {
				t.Fatalf("scan_completed coverage is not semantic-complete and safe: %+v", event.Coverage)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read worker output: %v", err)
	}
	if !seenCompleted {
		t.Fatal("worker output has no scan_completed event")
	}
	if len(seenResolvers) != len(wantResolvers) {
		t.Fatalf("worker emitted semantic resolvers %d, want %d: %v", len(seenResolvers), len(wantResolvers), seenResolvers)
	}
	for resolver := range wantResolvers {
		if !seenResolvers[resolver] {
			t.Fatalf("worker output omitted semantic resolver %q", resolver)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
