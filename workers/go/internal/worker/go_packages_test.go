package worker

import (
	"fmt"
	"go/ast"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/tools/go/packages"
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
	poisonedTarget := filepath.Join(t.TempDir(), "safe"+string(os.PathListSeparator)+"injected")
	poisonedAlias := filepath.Join(t.TempDir(), "poisoned-bin")
	if err := os.MkdirAll(poisonedTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(poisonedTarget, poisonedAlias); err == nil {
		raw = strings.Join([]string{safe, poisonedAlias}, string(os.PathListSeparator))
		entries = safePathEntries(root, raw)
		if len(entries) != 1 || entries[0] != resolved {
			t.Fatalf("resolved PATH separator was reintroduced: %v", entries)
		}
		t.Setenv("GOPATH", poisonedAlias)
		if entries := safePathListEnvironmentValues(root, "GOPATH"); len(entries) != 0 {
			t.Fatalf("resolved GOPATH separator was reintroduced: %v", entries)
		}
	}
}

func TestSafeGoCommandPathRejectsResolvedDirectoryWithPathSeparator(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell executable fixture is Unix-only")
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
	target := filepath.Join(parent, "safe"+string(os.PathListSeparator)+"injected")
	alias := filepath.Join(parent, "bin-link")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(target, "go"), "#!/bin/sh\nexit 0\n")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	t.Setenv("PATH", alias+string(os.PathListSeparator)+filepath.Dir(realGo))
	if _, err := safeGoCommandPath(root); err == nil {
		t.Fatal("Go command path whose resolved directory contains a path-list separator was accepted")
	}
}

func TestConstrainedGoEnvironmentDisablesTelemetryInNeutralConfig(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	pathValue, err := safeGoCommandPath(root)
	if err != nil {
		t.Skipf("safe Go command unavailable: %v", err)
	}
	environment, err := constrainedGoEnvironment(root, pathValue)
	if err != nil {
		t.Fatal(err)
	}
	defer environment.cleanup()
	if environment.NeutralRoot == "" || isWithinRoot(root, environment.NeutralRoot) {
		t.Fatalf("neutral environment is not isolated: %+v", environment)
	}
	mode, err := os.ReadFile(environment.TelemetryModePath)
	if err != nil || string(mode) != "off 2000-01-01" {
		t.Fatalf("telemetry mode = %q, %v", mode, err)
	}
	for _, key := range []string{"HOME", "XDG_CONFIG_HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "GOCACHE", "TMPDIR", "TEMP", "TMP"} {
		value := environmentValue(environment.Values, key)
		if value == "" || !isWithinRoot(environment.NeutralRoot, value) || isWithinRoot(root, value) {
			t.Fatalf("%s is not confined to the neutral environment: %q", key, value)
		}
	}
	if environmentValue(environment.Values, "GOTELEMETRY") != "" {
		t.Fatal("GOTELEMETRY must not be treated as a settable environment variable")
	}
	if environmentValue(environment.Values, "GOROOT") != "" {
		t.Fatal("GOROOT must be discovered by the selected Go command, including from a trimpath-built worker")
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("Go command unavailable: %v", err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(realGo, "env", "GOTELEMETRY", "GOTELEMETRYDIR")
	command.Dir = root
	command.Env = append(append([]string(nil), environment.Values...), "GOWORK=off")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(output), "\r\n", "\n")), "\n")
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
	}
	if len(lines) != 2 || lines[0] != "off" || filepath.Clean(lines[1]) != filepath.Dir(environment.TelemetryModePath) {
		t.Fatalf("isolated Go telemetry state = %q; mode path=%q", output, environment.TelemetryModePath)
	}
}

func TestGoPackagesLoadsTypedPackagesInDeterministicOrder(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/typed\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "typed.go"), "package typed\n\ntype Greeter interface { Greet() string }\ntype Person struct{}\nfunc (Person) Greet() string { return \"hello\" }\nfunc Call[T Greeter](value T) string { return value.Greet() }\nconst Answer = 42\nfunc Value() int { return Answer }\n")
	writeTestFile(t, filepath.Join(root, "typed_test.go"), "package typed_test\n\nimport \"example.com/typed\"\n\nfunc ExampleValue() { _ = typed.Value(); _ = typed.Call(typed.Person{}) }\n")
	module, diagnostics := parseGoMod(filepath.Join(root, "go.mod"), root)
	if len(diagnostics) != 0 {
		t.Fatalf("parseGoMod diagnostics = %+v", diagnostics)
	}

	inventory := loadGoPackagesInventory(root, []Module{module}, WorkFile{}, nil)
	if inventory.Status != "loaded" || inventory.Fallback {
		t.Fatalf("typed load status = %q fallback=%v diagnostics=%+v", inventory.Status, inventory.Fallback, inventory.Diagnostics)
	}
	if len(inventory.TypedPackages) == 0 {
		t.Fatalf("typed packages were not retained: %+v", inventory)
	}

	keys := make([]string, 0, len(inventory.TypedPackages))
	foundDefinition := false
	foundUse := false
	foundSelection := false
	foundInstance := false
	for _, pkg := range inventory.TypedPackages {
		if pkg.Types == nil || pkg.TypesInfo == nil || pkg.TypesSizes == nil || pkg.FileSet == nil {
			t.Fatalf("package %q is missing typed state: %+v", pkg.ID, pkg)
		}
		keys = append(keys, pkg.ModulePath+"\x00"+pkg.ID+"\x00"+pkg.PkgPath+"\x00"+pkg.ForTest)
		filePaths := make([]string, 0, len(pkg.Files))
		for _, file := range pkg.Files {
			if file.Syntax == nil {
				t.Fatalf("package %q retained nil syntax for %q", pkg.ID, file.Path)
			}
			filePaths = append(filePaths, file.Path)
			ast.Inspect(file.Syntax, func(node ast.Node) bool {
				identifier, ok := node.(*ast.Ident)
				if ok && identifier.Name == "Value" && pkg.TypesInfo.Defs[identifier] != nil {
					foundDefinition = true
				}
				if ok && pkg.TypesInfo.Uses[identifier] != nil {
					foundUse = true
				}
				return true
			})
		}
		foundSelection = foundSelection || len(pkg.TypesInfo.Selections) > 0
		foundInstance = foundInstance || len(pkg.TypesInfo.Instances) > 0
		if !sort.StringsAreSorted(filePaths) {
			t.Fatalf("typed files are not deterministic for %q: %v", pkg.ID, filePaths)
		}
	}
	if !sort.StringsAreSorted(keys) {
		t.Fatalf("typed packages are not deterministic: %v", keys)
	}
	if !foundDefinition {
		t.Fatal("TypesInfo did not retain the Value definition")
	}
	if !foundUse || !foundSelection || !foundInstance {
		t.Fatalf("TypesInfo maps are incomplete: uses=%v selections=%v instances=%v", foundUse, foundSelection, foundInstance)
	}
}

func TestGoPackagesTimeoutFallsBackAtModuleBoundary(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/timeout\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "timeout.go"), "package timeout\n")
	module, diagnostics := parseGoMod(filepath.Join(root, "go.mod"), root)
	if len(diagnostics) != 0 {
		t.Fatalf("parseGoMod diagnostics = %+v", diagnostics)
	}
	loader := func(config *packages.Config, _ ...string) ([]*packages.Package, error) {
		<-config.Context.Done()
		return nil, config.Context.Err()
	}

	inventory := loadGoPackagesInventoryWith(root, []Module{module}, WorkFile{}, nil, loader, time.Millisecond)
	if inventory.Status != "fallback" || !inventory.Fallback {
		t.Fatalf("timeout status = %q fallback=%v", inventory.Status, inventory.Fallback)
	}
	if !hasDiagnostic(inventory.Diagnostics, "go_packages_load_timeout") {
		t.Fatalf("timeout diagnostic missing: %+v", inventory.Diagnostics)
	}
	if len(inventory.TypedPackages) != 0 {
		t.Fatalf("timed-out module leaked typed packages: %+v", inventory.TypedPackages)
	}
}

func TestGoPackagesRejectsSourceSymlinkBeforeInvokingLoader(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	outside := filepath.Join(t.TempDir(), "outside.go")
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/symlink\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "safe.go"), "package symlink\n")
	writeTestFile(t, outside, "package symlink\n\nconst Leaked = true\n")
	if err := os.Symlink(outside, filepath.Join(root, "leaked.go")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	module, diagnostics := parseGoMod(filepath.Join(root, "go.mod"), root)
	if len(diagnostics) != 0 {
		t.Fatalf("parseGoMod diagnostics = %+v", diagnostics)
	}
	loaderCalled := false
	loader := func(_ *packages.Config, _ ...string) ([]*packages.Package, error) {
		loaderCalled = true
		return nil, nil
	}

	inventory := loadGoPackagesInventoryWith(root, []Module{module}, WorkFile{}, nil, loader, time.Second)
	if loaderCalled {
		t.Fatal("typed loader was invoked despite a source symlink")
	}
	if inventory.Status != "fallback" || !hasDiagnostic(inventory.Diagnostics, "go_packages_source_confinement") {
		t.Fatalf("source symlink fallback missing: %+v", inventory)
	}
}

func TestGoPackagesRejectsInjectedWorkspaceDirectiveBeforeInvokingLoader(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/injection\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "injection.go"), "package injection\n")
	writeTestFile(t, filepath.Join(root, "go.work"), "go \"1.26.1\\nuse\\x20/outside\\n//\"\n\nuse .\n")
	module, moduleDiagnostics := parseGoMod(filepath.Join(root, "go.mod"), root)
	work, workDiagnostics := parseGoWork(filepath.Join(root, "go.work"), root)
	if len(moduleDiagnostics) != 0 || len(workDiagnostics) != 0 || work.ParseIssues != 0 {
		t.Fatalf("injection fixture should reach strict mirror validation: module=%+v work=%+v parsed=%+v", moduleDiagnostics, workDiagnostics, work)
	}
	loaderCalled := false
	loader := func(_ *packages.Config, _ ...string) ([]*packages.Package, error) {
		loaderCalled = true
		return nil, nil
	}

	inventory := loadGoPackagesInventoryWith(root, []Module{module}, work, nil, loader, time.Second)
	if loaderCalled {
		t.Fatal("typed loader was invoked with an injected workspace directive")
	}
	if inventory.Status != "fallback" || !hasDiagnostic(inventory.Diagnostics, "go_packages_workspace_disabled") {
		t.Fatalf("workspace injection fallback missing: %+v", inventory)
	}
}

func TestGoPackagesRejectsSymlinkedWorkspaceBeforeInvokingLoader(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/work-link\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "work.go"), "package worklink\n")
	target := filepath.Join(root, "config", "go.work")
	writeTestFile(t, target, "go 1.26.1\n\nuse .\n")
	workPath := filepath.Join(root, "go.work")
	if err := os.Symlink(target, workPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	module, _ := parseGoMod(filepath.Join(root, "go.mod"), root)
	work, diagnostics := parseGoWork(workPath, root)
	if len(diagnostics) != 0 {
		t.Fatalf("parseGoWork diagnostics = %+v", diagnostics)
	}
	loaderCalled := false
	loader := func(_ *packages.Config, _ ...string) ([]*packages.Package, error) {
		loaderCalled = true
		return nil, nil
	}

	inventory := loadGoPackagesInventoryWith(root, []Module{module}, work, nil, loader, time.Second)
	if loaderCalled {
		t.Fatal("typed loader was invoked with a symlinked go.work")
	}
	if inventory.Status != "fallback" || !hasDiagnostic(inventory.Diagnostics, "go_packages_workspace_disabled") {
		t.Fatalf("symlinked workspace fallback missing: %+v", inventory)
	}
}

func TestGoPackagesSymlinkedWorkspaceRetainsIndependentTypedModule(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	workspace := filepath.Join(root, "workspace")
	independent := filepath.Join(root, "independent")
	target := filepath.Join(root, "config", "go.work")
	writeTestFile(t, target, "go 1.26.1\n\nuse ./workspace\n")
	if err := os.Symlink(target, filepath.Join(root, "go.work")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	writeTestFile(t, filepath.Join(workspace, "go.mod"), "module example.com/workspace\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(workspace, "workspace.go"), "package workspace\n")
	writeTestFile(t, filepath.Join(independent, "go.mod"), "module example.com/independent\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(independent, "independent.go"), "package independent\n\nfunc Value() int { return 1 }\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Properties["go_packages_status"] != "partial" {
		t.Fatalf("symlinked workspace status = %q; diagnostics=%+v", result.Profile.Properties["go_packages_status"], result.Diagnostics)
	}
	typedCount, err := strconv.Atoi(result.Profile.Properties["go_packages_typed_packages"])
	if err != nil || typedCount < 1 {
		t.Fatalf("independent module types were lost: properties=%+v", result.Profile.Properties)
	}
	if !hasDiagnostic(result.Diagnostics, "go_packages_workspace_disabled") || result.Coverage.ProjectCodeExecuted {
		t.Fatalf("symlinked workspace fallback was not retained safely: coverage=%+v diagnostics=%+v", result.Coverage, result.Diagnostics)
	}
}

func TestGoPackagesOutOfRootWorkspaceSymlinkMarksIndependentLoadPartial(t *testing.T) {
	parent := t.TempDir()
	repository := filepath.Join(parent, "repo")
	if err := os.MkdirAll(repository, 0o755); err != nil {
		t.Fatal(err)
	}
	root := canonicalTestRoot(t, repository)
	independent := filepath.Join(root, "independent")
	outsideWork := filepath.Join(parent, "outside", "go.work")
	writeTestFile(t, outsideWork, "go 1.26.1\n\nuse .\n")
	if err := os.Symlink(outsideWork, filepath.Join(root, "go.work")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	writeTestFile(t, filepath.Join(independent, "go.mod"), "module example.com/independent\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(independent, "independent.go"), "package independent\n\nfunc Value() int { return 1 }\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Properties["go_packages_status"] != "partial" {
		t.Fatalf("out-of-root workspace status = %q; diagnostics=%+v", result.Profile.Properties["go_packages_status"], result.Diagnostics)
	}
	typedCount, err := strconv.Atoi(result.Profile.Properties["go_packages_typed_packages"])
	if err != nil || typedCount < 1 {
		t.Fatalf("independent module types were lost: properties=%+v", result.Profile.Properties)
	}
	if !hasDiagnostic(result.Diagnostics, "go_packages_workspace_disabled") || result.Coverage.ProjectCodeExecuted {
		t.Fatalf("out-of-root workspace fallback was not retained safely: coverage=%+v diagnostics=%+v", result.Coverage, result.Diagnostics)
	}
	for _, node := range result.Nodes {
		if node.Kind == "workspace" {
			if enabled, _ := node.Properties["go_work"].(bool); enabled {
				t.Fatalf("untrusted go.work was promoted to workspace metadata: %+v", node)
			}
		}
	}
}

func TestGoPackagesRejectsOfficialOutsideReplacementBeforeInvokingLoader(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	outside := filepath.Join(t.TempDir(), "outside module")
	writeTestFile(t, filepath.Join(outside, "go.mod"), "module example.com/outside\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(outside, "outside.go"), "package outside\n")
	moduleText := fmt.Sprintf("module example.com/replacement\n\ngo 1.26.1\n\nreplace example.com/outside => %s\n", strconv.Quote(filepath.ToSlash(outside)))
	writeTestFile(t, filepath.Join(root, "go.mod"), moduleText)
	writeTestFile(t, filepath.Join(root, "replacement.go"), "package replacement\n")
	module, diagnostics := parseGoMod(filepath.Join(root, "go.mod"), root)
	if len(diagnostics) != 0 || module.ParseIssues != 0 {
		t.Fatalf("fixture should expose the inventory parser ambiguity: module=%+v diagnostics=%+v", module, diagnostics)
	}
	loaderCalled := false
	loader := func(_ *packages.Config, _ ...string) ([]*packages.Package, error) {
		loaderCalled = true
		return nil, nil
	}

	inventory := loadGoPackagesInventoryWith(root, []Module{module}, WorkFile{}, nil, loader, time.Second)
	if loaderCalled {
		t.Fatal("typed loader was invoked with an official outside-root replacement")
	}
	if inventory.Status != "fallback" || !hasDiagnostic(inventory.Diagnostics, "go_packages_module_confined_fallback") {
		t.Fatalf("outside replacement fallback missing: %+v", inventory)
	}
}

func TestGoPackagesPreflightsEveryWorkspaceMemberBeforeFirstLoad(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	moduleA := filepath.Join(root, "a")
	moduleB := filepath.Join(root, "b")
	outside := filepath.Join(t.TempDir(), "outside.go")
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.26.1\n\nuse (\n\t./a\n\t./b\n)\n")
	writeTestFile(t, filepath.Join(moduleA, "go.mod"), "module example.com/a\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(moduleA, "a.go"), "package a\n")
	writeTestFile(t, filepath.Join(moduleB, "go.mod"), "module example.com/b\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(moduleB, "b.go"), "package b\n")
	writeTestFile(t, outside, "package b\n\nconst Outside = true\n")
	if err := os.Symlink(outside, filepath.Join(moduleB, "unsafe.go")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	moduleAInfo, _ := parseGoMod(filepath.Join(moduleA, "go.mod"), root)
	moduleBInfo, _ := parseGoMod(filepath.Join(moduleB, "go.mod"), root)
	work, diagnostics := parseGoWork(filepath.Join(root, "go.work"), root)
	if len(diagnostics) != 0 {
		t.Fatalf("parseGoWork diagnostics = %+v", diagnostics)
	}
	loaderCalled := false
	loader := func(_ *packages.Config, _ ...string) ([]*packages.Package, error) {
		loaderCalled = true
		return nil, nil
	}

	inventory := loadGoPackagesInventoryWith(root, []Module{moduleAInfo, moduleBInfo}, work, nil, loader, time.Second)
	if loaderCalled {
		t.Fatal("the first workspace module loaded before the later unsafe member was preflighted")
	}
	if inventory.Status != "fallback" || !hasDiagnostic(inventory.Diagnostics, "go_packages_source_confinement") {
		t.Fatalf("workspace-wide source fallback missing: %+v", inventory)
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
	argsLogPath := filepath.Join(parent, "go-arguments.log")
	driverMarker := filepath.Join(root, "external-driver-was-run")
	generateMarker := filepath.Join(root, "generate-was-run")
	driverPath := filepath.Join(root, "project-driver")
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/safe\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package safe\n\nimport _ \"embed\"\n\n//go:embed asset.txt\nvar asset string\n\n//go:generate sh -c \"touch generate-was-run\"\nfunc Safe() {}\n")
	writeTestFile(t, filepath.Join(root, "main_test.go"), "package safe_test\n\nimport \"example.com/safe\"\n\nfunc Example() { safe.Safe() }\n")
	writeTestFile(t, filepath.Join(root, "asset.txt"), "safe static asset\n")
	writeExecutable(t, driverPath, "#!/bin/sh\ntouch "+shellQuote(driverMarker)+"\nprintf '{\"NotHandled\":true}'\n")
	wrapper := "#!/bin/sh\n" +
		"printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\\n' \"$GOPACKAGESDRIVER\" \"$GOPROXY\" \"$GOTOOLCHAIN\" \"$GOFLAGS\" \"$CGO_ENABLED\" \"$GOENV\" \"$XDG_CONFIG_HOME\" \"$HOME\" \"$PWD\" >> " + shellQuote(logPath) + "\n" +
		"printf '%s\\n' \"$*\" >> " + shellQuote(argsLogPath) + "\n" +
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
	if result.Profile.Properties["go_packages_safe_mode"] != "offline,readonly,no-external-driver,cgo-disabled,telemetry-disabled" {
		t.Fatalf("safe mode properties missing: %+v", result.Profile.Properties)
	}
	for _, key := range []string{"go_packages_modules", "go_packages_packages", "go_packages_active_files", "go_packages_compiled_files", "go_packages_embed_files", "go_packages_test_variants", "go_packages_typed_packages", "go_packages_typed_files"} {
		count, err := strconv.Atoi(result.Profile.Properties[key])
		if err != nil || count < 1 {
			t.Fatalf("%s did not record constrained metadata: properties=%+v", key, result.Profile.Properties)
		}
	}
	if result.Profile.Properties["go_packages_query"] != "syntax-types-types-info" {
		t.Fatalf("typed query property missing: %+v", result.Profile.Properties)
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
		if len(fields) != 9 {
			t.Fatalf("unexpected wrapper log line: %q", line)
		}
		if fields[0] != "off" || fields[1] != "off" || fields[2] != "local" || fields[3] != "-mod=readonly" || fields[4] != "0" || fields[5] != "off" {
			t.Fatalf("go command received an unsafe environment: %q", line)
		}
		if fields[6] == "" || isWithinRoot(canonicalRoot, fields[6]) || fields[7] == "" || isWithinRoot(canonicalRoot, fields[7]) {
			t.Fatalf("go command HOME is not isolated outside the scan root: %q", line)
		}
		if filepath.Dir(fields[6]) != filepath.Dir(fields[7]) {
			t.Fatalf("Go config and HOME do not share one neutral root: %q", line)
		}
		if fields[8] != canonicalRoot {
			t.Fatalf("go command cwd = %q; want confined module %q", fields[8], canonicalRoot)
		}
	}
	argsBytes, err := os.ReadFile(argsLogPath)
	if err != nil {
		t.Fatal(err)
	}
	listSeen := false
	for _, line := range strings.Split(strings.TrimSpace(string(argsBytes)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] != "env" && fields[0] != "list" {
			t.Fatalf("go/packages invoked unexpected Go verb: %q", line)
		}
		if fields[0] == "list" {
			if !strings.Contains(line, "-json=") {
				continue
			}
			listSeen = true
			for _, flag := range []string{"-export=false", "-compiled=true", "-deps=true", "-buildvcs=false", "-pgo=off"} {
				if !strings.Contains(line, flag) {
					t.Fatalf("typed go list omitted %s: %q", flag, line)
				}
			}
		}
	}
	if !listSeen {
		t.Fatalf("go/packages did not invoke go list: %q", argsBytes)
	}
	if result.Coverage.ProjectCodeExecuted {
		t.Fatal("safe metadata load reported project code execution")
	}
}

func TestGoPackagesPartialFailureRetainsGoodTypesAndParserSites(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	good := filepath.Join(root, "a-good")
	bad := filepath.Join(root, "z-bad")
	writeTestFile(t, filepath.Join(good, "go.mod"), "module example.com/good\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(good, "good.go"), "package good\n\nfunc Good() int { return 1 }\n")
	writeTestFile(t, filepath.Join(bad, "go.mod"), "module example.com/bad\n\ngo 1.26.1\n\nrequire example.invalid/missing v1.2.3\n")
	writeTestFile(t, filepath.Join(bad, "bad.go"), "package bad\n\nimport _ \"example.invalid/missing/pkg\"\n")
	moduleCache := filepath.Join(t.TempDir(), "empty-module-cache")
	if err := os.MkdirAll(moduleCache, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOMODCACHE", moduleCache)
	t.Setenv("GOPATH", filepath.Join(t.TempDir(), "isolated-gopath"))

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Properties["go_packages_status"] != "partial" {
		t.Fatalf("go_packages_status = %q; want partial; diagnostics=%+v", result.Profile.Properties["go_packages_status"], result.Diagnostics)
	}
	typedCount, err := strconv.Atoi(result.Profile.Properties["go_packages_typed_packages"])
	if err != nil || typedCount < 1 {
		t.Fatalf("good module types were not retained: properties=%+v", result.Profile.Properties)
	}
	if !hasDiagnostic(result.Diagnostics, "go_packages_package_error") && !hasDiagnostic(result.Diagnostics, "go_packages_load_failed") && !hasDiagnostic(result.Diagnostics, "go_packages_typed_incomplete") {
		t.Fatalf("failed module diagnostic missing: %+v", result.Diagnostics)
	}
	assertSiteStatus(t, result.Sites, "side_effect_import", "example.invalid/missing/pkg", "external")
	if result.Coverage.ProjectCodeExecuted {
		t.Fatal("partial typed load reported project code execution")
	}
	if !containsString(result.Coverage.Reasons, "go-packages-parser-fallback") {
		t.Fatalf("partial fallback reason missing: %+v", result.Coverage)
	}
}

func TestGoPackagesIndependentPreflightFailureIsPartial(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	good := filepath.Join(root, "a-good")
	bad := filepath.Join(root, "z-bad")
	outside := filepath.Join(t.TempDir(), "outside.go")
	writeTestFile(t, filepath.Join(good, "go.mod"), "module example.com/good-preflight\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(good, "good.go"), "package good\n\nfunc Good() int { return 1 }\n")
	writeTestFile(t, filepath.Join(bad, "go.mod"), "module example.com/bad-preflight\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(bad, "bad.go"), "package bad\n")
	writeTestFile(t, outside, "package bad\n\nconst Outside = true\n")
	if err := os.Symlink(outside, filepath.Join(bad, "unsafe.go")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Properties["go_packages_status"] != "partial" {
		t.Fatalf("independent preflight status = %q; diagnostics=%+v", result.Profile.Properties["go_packages_status"], result.Diagnostics)
	}
	typedCount, err := strconv.Atoi(result.Profile.Properties["go_packages_typed_packages"])
	if err != nil || typedCount < 1 {
		t.Fatalf("safe independent module types were lost: properties=%+v", result.Profile.Properties)
	}
	if !hasDiagnostic(result.Diagnostics, "go_packages_source_confinement") || result.Coverage.ProjectCodeExecuted {
		t.Fatalf("unsafe module fallback was not retained safely: coverage=%+v diagnostics=%+v", result.Coverage, result.Diagnostics)
	}
}

func TestGoPackagesNestedModuleSymlinkDoesNotDisableParent(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	nested := filepath.Join(root, "nested")
	outside := filepath.Join(t.TempDir(), "outside.go")
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/parent\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "parent.go"), "package parent\n\nfunc Parent() int { return 1 }\n")
	writeTestFile(t, filepath.Join(nested, "go.mod"), "module example.com/nested\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(nested, "nested.go"), "package nested\n")
	writeTestFile(t, outside, "package nested\n\nconst Outside = true\n")
	if err := os.Symlink(outside, filepath.Join(nested, "unsafe.go")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Properties["go_packages_status"] != "partial" {
		t.Fatalf("nested module preflight status = %q; diagnostics=%+v", result.Profile.Properties["go_packages_status"], result.Diagnostics)
	}
	typedCount, err := strconv.Atoi(result.Profile.Properties["go_packages_typed_packages"])
	if err != nil || typedCount < 1 {
		t.Fatalf("parent module types were lost: properties=%+v", result.Profile.Properties)
	}
	if !hasDiagnostic(result.Diagnostics, "go_packages_source_confinement") || result.Coverage.ProjectCodeExecuted {
		t.Fatalf("nested module fallback was not retained safely: coverage=%+v diagnostics=%+v", result.Coverage, result.Diagnostics)
	}
}

func TestGoPackagesUnsafeNestedReplacementStillDisablesParent(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	nested := filepath.Join(root, "nested")
	outside := filepath.Join(t.TempDir(), "outside.go")
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/parent\n\ngo 1.26.1\n\nrequire example.com/nested v0.0.0\nreplace example.com/nested => ./nested\n")
	writeTestFile(t, filepath.Join(root, "parent.go"), "package parent\n\nimport \"example.com/nested\"\n\nfunc Parent() int { return nested.Value() }\n")
	writeTestFile(t, filepath.Join(nested, "go.mod"), "module example.com/nested\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(nested, "nested.go"), "package nested\n\nfunc Value() int { return 1 }\n")
	writeTestFile(t, outside, "package nested\n\nconst Outside = true\n")
	if err := os.Symlink(outside, filepath.Join(nested, "unsafe.go")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Properties["go_packages_status"] != "fallback" {
		t.Fatalf("unsafe nested replacement status = %q; diagnostics=%+v", result.Profile.Properties["go_packages_status"], result.Diagnostics)
	}
	if result.Profile.Properties["go_packages_typed_packages"] != "0" {
		t.Fatalf("unsafe replacement leaked typed packages: properties=%+v", result.Profile.Properties)
	}
	if !hasDiagnostic(result.Diagnostics, "go_packages_source_confinement") || !hasDiagnostic(result.Diagnostics, "go_packages_module_confined_fallback") || result.Coverage.ProjectCodeExecuted {
		t.Fatalf("unsafe replacement did not fail closed: coverage=%+v diagnostics=%+v", result.Coverage, result.Diagnostics)
	}
}

func TestGoPackagesUnsafeWorkspaceRetainsIndependentTypedModule(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	workspaceA := filepath.Join(root, "workspace-a")
	workspaceB := filepath.Join(root, "workspace-b")
	independent := filepath.Join(root, "independent")
	outside := filepath.Join(t.TempDir(), "outside.go")
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.26.1\n\nuse (\n\t./workspace-a\n\t./workspace-b\n)\n")
	writeTestFile(t, filepath.Join(workspaceA, "go.mod"), "module example.com/workspace-a\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(workspaceA, "a.go"), "package workspacea\n")
	writeTestFile(t, filepath.Join(workspaceB, "go.mod"), "module example.com/workspace-b\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(workspaceB, "b.go"), "package workspaceb\n")
	writeTestFile(t, filepath.Join(independent, "go.mod"), "module example.com/independent\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(independent, "independent.go"), "package independent\n\nfunc Value() int { return 1 }\n")
	writeTestFile(t, outside, "package workspaceb\n\nconst Outside = true\n")
	if err := os.Symlink(outside, filepath.Join(workspaceB, "unsafe.go")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Properties["go_packages_status"] != "partial" {
		t.Fatalf("unsafe workspace status = %q; diagnostics=%+v", result.Profile.Properties["go_packages_status"], result.Diagnostics)
	}
	typedCount, err := strconv.Atoi(result.Profile.Properties["go_packages_typed_packages"])
	if err != nil || typedCount < 1 {
		t.Fatalf("independent module types were lost: properties=%+v", result.Profile.Properties)
	}
	if !hasDiagnostic(result.Diagnostics, "go_packages_source_confinement") || !hasDiagnostic(result.Diagnostics, "go_packages_workspace_disabled") {
		t.Fatalf("workspace fallback diagnostics missing: %+v", result.Diagnostics)
	}
	if result.Coverage.ProjectCodeExecuted {
		t.Fatal("workspace fallback reported project code execution")
	}
}

func TestGoPackagesInvalidEmptyWorkspaceMarksIndependentLoadPartial(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	independent := filepath.Join(root, "independent")
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.26.1\n\nuse ./missing\n")
	writeTestFile(t, filepath.Join(independent, "go.mod"), "module example.com/independent\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(independent, "independent.go"), "package independent\n\nfunc Value() int { return 1 }\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Properties["go_packages_status"] != "partial" {
		t.Fatalf("invalid empty workspace status = %q; diagnostics=%+v", result.Profile.Properties["go_packages_status"], result.Diagnostics)
	}
	typedCount, err := strconv.Atoi(result.Profile.Properties["go_packages_typed_packages"])
	if err != nil || typedCount < 1 {
		t.Fatalf("independent module types were lost: properties=%+v", result.Profile.Properties)
	}
	if !hasDiagnostic(result.Diagnostics, "go_packages_workspace_disabled") {
		t.Fatalf("workspace fallback diagnostic missing: %+v", result.Diagnostics)
	}
	if result.Coverage.ProjectCodeExecuted || !containsString(result.Coverage.Reasons, "go-packages-parser-fallback") {
		t.Fatalf("workspace fallback coverage missing: %+v", result.Coverage)
	}
}

func TestGoPackagesUsesIsolatedWorkspaceWithoutWritingGoWorkSum(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	moduleA := filepath.Join(root, "a")
	moduleB := filepath.Join(root, "b")
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.26.1\n\nuse (\n\t./a\n\t./b\n)\n")
	writeTestFile(t, filepath.Join(moduleA, "go.mod"), "module example.com/a\n\ngo 1.26.1\n\nrequire example.com/b v0.0.0\n")
	writeTestFile(t, filepath.Join(moduleA, "a.go"), "package a\n\nimport \"example.com/b\"\n\nfunc A() int { return b.B() }\n")
	writeTestFile(t, filepath.Join(moduleB, "go.mod"), "module example.com/b\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(moduleB, "b.go"), "package b\n\nfunc B() int { return 1 }\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Properties["go_packages_status"] != "loaded" {
		t.Fatalf("isolated workspace typed load failed: properties=%+v diagnostics=%+v", result.Profile.Properties, result.Diagnostics)
	}
	if _, err := os.Stat(filepath.Join(root, "go.work.sum")); !os.IsNotExist(err) {
		t.Fatalf("typed workspace load wrote go.work.sum in the repository: %v", err)
	}
	for _, module := range []string{"a", "b"} {
		if _, err := os.Stat(filepath.Join(root, module, "go.sum")); !os.IsNotExist(err) {
			t.Fatalf("typed workspace load wrote %s/go.sum: %v", module, err)
		}
	}
	if result.Coverage.ProjectCodeExecuted {
		t.Fatal("isolated workspace typed load reported project code execution")
	}
}

func TestGoPackagesRedactsIsolatedWorkspacePathAndMirrorsSum(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.26.1\n\nuse .\n")
	writeTestFile(t, filepath.Join(root, "go.work.sum"), "example.com/dep v1.0.0 h1:fixture\n")
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/work\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "work.go"), "package work\n")
	module, moduleDiagnostics := parseGoMod(filepath.Join(root, "go.mod"), root)
	work, workDiagnostics := parseGoWork(filepath.Join(root, "go.work"), root)
	if len(moduleDiagnostics) != 0 || len(workDiagnostics) != 0 {
		t.Fatalf("fixture diagnostics: module=%+v work=%+v", moduleDiagnostics, workDiagnostics)
	}
	loader := func(config *packages.Config, _ ...string) ([]*packages.Package, error) {
		goWork := ""
		for _, entry := range config.Env {
			if strings.HasPrefix(entry, "GOWORK=") {
				goWork = strings.TrimPrefix(entry, "GOWORK=")
				break
			}
		}
		if goWork == "" || goWork == work.Path || isWithinRoot(root, goWork) {
			t.Fatalf("GOWORK was not isolated: %q", goWork)
		}
		mirroredSum, err := os.ReadFile(filepath.Join(filepath.Dir(goWork), "go.work.sum"))
		if err != nil || string(mirroredSum) != "example.com/dep v1.0.0 h1:fixture\n" {
			t.Fatalf("go.work.sum mirror = %q, %v", mirroredSum, err)
		}
		return nil, fmt.Errorf("isolated workspace %s failed", goWork)
	}

	messages := make([]string, 0, 2)
	for range 2 {
		inventory := loadGoPackagesInventoryWith(root, []Module{module}, work, nil, loader, time.Second)
		for _, diagnostic := range inventory.Diagnostics {
			if diagnostic.Code == "go_packages_load_failed" {
				messages = append(messages, diagnostic.Message)
			}
		}
	}
	if len(messages) != 2 || messages[0] != messages[1] {
		t.Fatalf("isolated workspace diagnostics are not deterministic: %v", messages)
	}
	if strings.Contains(messages[0], "depgraph-go-work-") || !strings.Contains(messages[0], "$GOWORK") {
		t.Fatalf("isolated workspace path was not redacted: %q", messages[0])
	}
	originalSum, err := os.ReadFile(filepath.Join(root, "go.work.sum"))
	if err != nil || string(originalSum) != "example.com/dep v1.0.0 h1:fixture\n" {
		t.Fatalf("repository go.work.sum changed: %q, %v", originalSum, err)
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

func canonicalTestRoot(t *testing.T, root string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(resolved)
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

func environmentValue(environment []string, key string) string {
	prefix := key + "="
	for _, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}
