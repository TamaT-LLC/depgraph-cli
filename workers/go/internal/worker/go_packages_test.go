package worker

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestSafePathEntriesRejectRelativeAndRepositoryDirectories(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	safe := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(safe, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := strings.Join([]string{".", "", root, safe, safe}, string(os.PathListSeparator))
	entries := safePathEntries(root, raw)
	if len(entries) != 1 {
		t.Fatalf("safePathEntries() = %v; want only %q", entries, safe)
	}
	resolved, err := filepath.EvalSymlinks(safe)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0] != resolved {
		t.Fatalf("safePathEntries()[0] = %q; want %q", entries[0], resolved)
	}
}

func TestGoPackagesDoesNotRunGoCommandFromScanRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell marker fixture is Unix-only")
	}
	root := t.TempDir()
	marker := filepath.Join(root, "target-go-was-run")
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/safe\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package safe\n")
	writeExecutable(t, filepath.Join(root, "go"), "#!/bin/sh\ntouch "+shellQuote(marker)+"\nexit 99\n")
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("the target repository's go command was executed: %v", err)
	}
	if result.Profile.Properties["go_packages_status"] != "fallback" {
		t.Fatalf("go_packages_status = %q; want fallback", result.Profile.Properties["go_packages_status"])
	}
	if !hasDiagnostic(result.Diagnostics, "go_packages_unsafe_tool_path") {
		t.Fatalf("missing unsafe tool path diagnostic: %+v", result.Diagnostics)
	}
	if result.Coverage.FilesAnalyzed != 2 || result.Coverage.ProjectCodeExecuted {
		t.Fatalf("parser fallback did not retain safe inventory: %+v", result.Coverage)
	}
}

func TestGoPackagesUsesConstrainedEnvironmentWithoutRunningProjectHooks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell wrapper fixture is Unix-only")
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("Go command unavailable: %v", err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}

	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	bin := filepath.Join(parent, "bin")
	logPath := filepath.Join(parent, "go-environment.log")
	driverMarker := filepath.Join(root, "external-driver-was-run")
	generateMarker := filepath.Join(root, "generate-was-run")
	driverPath := filepath.Join(root, "project-driver")
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/safe\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package safe\n\nimport _ \"embed\"\n\n//go:embed asset.txt\nvar asset string\n\n//go:generate sh -c \"touch generate-was-run\"\nfunc Safe() {}\n")
	writeTestFile(t, filepath.Join(root, "main_test.go"), "package safe_test\n\nimport \"example.com/safe\"\n\nfunc Example() { safe.Safe() }\n")
	writeTestFile(t, filepath.Join(root, "asset.txt"), "safe static asset\n")
	writeExecutable(t, driverPath, "#!/bin/sh\ntouch "+shellQuote(driverMarker)+"\nprintf '{\"NotHandled\":true}'\n")
	wrapper := "#!/bin/sh\n" +
		"printf '%s|%s|%s|%s|%s|%s|%s\\n' \"$GOPACKAGESDRIVER\" \"$GOPROXY\" \"$GOTOOLCHAIN\" \"$GOFLAGS\" \"$CGO_ENABLED\" \"$GOENV\" \"$PWD\" >> " + shellQuote(logPath) + "\n" +
		"exec " + shellQuote(realGo) + " \"$@\"\n"
	writeExecutable(t, filepath.Join(bin, "go"), wrapper)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+filepath.Dir(realGo)+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOPACKAGESDRIVER", driverPath)

	beforeModule, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	afterModule, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if string(afterModule) != string(beforeModule) {
		t.Fatal("go/packages modified go.mod despite read-only mode")
	}
	if _, err := os.Stat(filepath.Join(root, "go.sum")); !os.IsNotExist(err) {
		t.Fatalf("go/packages created go.sum despite read-only mode: %v", err)
	}
	for _, marker := range []string{driverMarker, generateMarker} {
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("project hook created marker %q: %v", marker, err)
		}
	}
	if result.Profile.Properties["go_packages_status"] != "loaded" {
		t.Fatalf("go_packages_status = %q; diagnostics=%+v", result.Profile.Properties["go_packages_status"], result.Diagnostics)
	}
	if result.Profile.Properties["go_packages_safe_mode"] != "offline,readonly,no-external-driver,cgo-disabled" {
		t.Fatalf("safe mode properties missing: %+v", result.Profile.Properties)
	}
	for _, key := range []string{"go_packages_modules", "go_packages_packages", "go_packages_active_files", "go_packages_compiled_files", "go_packages_embed_files", "go_packages_test_variants"} {
		count, err := strconv.Atoi(result.Profile.Properties[key])
		if err != nil || count < 1 {
			t.Fatalf("%s did not record constrained metadata: properties=%+v", key, result.Profile.Properties)
		}
	}
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(logBytes)), "\n") {
		fields := strings.Split(line, "|")
		if len(fields) != 7 {
			t.Fatalf("unexpected wrapper log line: %q", line)
		}
		if fields[0] != "off" || fields[1] != "off" || fields[2] != "local" || fields[3] != "-mod=readonly" || fields[4] != "0" || fields[5] != "off" {
			t.Fatalf("go command received an unsafe environment: %q", line)
		}
		if fields[6] != canonicalRoot {
			t.Fatalf("go command cwd = %q; want confined module %q", fields[6], canonicalRoot)
		}
	}
	if result.Coverage.ProjectCodeExecuted {
		t.Fatal("safe metadata load reported project code execution")
	}
}

func TestGoPackagesOfflineCacheFailureFallsBackToParser(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	moduleCache := filepath.Join(parent, "empty-module-cache")
	gopath := filepath.Join(parent, "isolated-gopath")
	moduleText := "module example.com/offline\n\ngo 1.26.1\n\nrequire example.invalid/missing v1.2.3\n"
	writeTestFile(t, filepath.Join(root, "go.mod"), moduleText)
	writeTestFile(t, filepath.Join(root, "offline.go"), "package offline\n\nimport _ \"example.invalid/missing/pkg\"\n")
	if err := os.MkdirAll(moduleCache, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOMODCACHE", moduleCache)
	t.Setenv("GOPATH", gopath)

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Properties["go_packages_status"] == "loaded" {
		t.Fatalf("missing offline dependency was reported as a complete load: properties=%+v diagnostics=%+v", result.Profile.Properties, result.Diagnostics)
	}
	if !hasDiagnostic(result.Diagnostics, "go_packages_package_error") && !hasDiagnostic(result.Diagnostics, "go_packages_load_failed") {
		t.Fatalf("missing offline fallback diagnostic: %+v", result.Diagnostics)
	}
	assertSiteStatus(t, result.Sites, "side_effect_import", "example.invalid/missing/pkg", "external")
	if result.Coverage.FilesAnalyzed != 2 || result.Coverage.FilesSkipped != 0 {
		t.Fatalf("parser fallback lost source inventory: %+v", result.Coverage)
	}
	if !containsString(result.Coverage.Reasons, "go-packages-parser-fallback") {
		t.Fatalf("fallback reason missing: %+v", result.Coverage)
	}
	afterModule, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if string(afterModule) != moduleText {
		t.Fatal("offline metadata load modified go.mod")
	}
	if _, err := os.Stat(filepath.Join(root, "go.sum")); !os.IsNotExist(err) {
		t.Fatalf("offline metadata load created go.sum: %v", err)
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	writeTestFile(t, path, content)
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func hasDiagnostic(diagnostics []Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
