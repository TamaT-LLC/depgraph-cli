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
