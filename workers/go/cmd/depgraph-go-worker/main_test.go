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
