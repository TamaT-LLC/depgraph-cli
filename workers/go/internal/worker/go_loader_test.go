package worker

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/tools/go/packages"
)

func TestGoLoaderTimeoutUsesTheWorkerBudgetAndRejectsInvalidValues(t *testing.T) {
	for _, test := range []struct {
		value string
		want  time.Duration
	}{
		{"300", 300 * time.Second},
		{"7", 7 * time.Second},
		{"", goPackagesLoadTimeout},
		{"0", goPackagesLoadTimeout},
		{"-1", goPackagesLoadTimeout},
		{"1s", goPackagesLoadTimeout},
		{"9223372037", goPackagesLoadTimeout},
		{"18446744073709551616", goPackagesLoadTimeout},
	} {
		t.Run(test.value, func(t *testing.T) {
			t.Setenv("DEPGRAPH_GO_LOAD_TIMEOUT_SECONDS", test.value)
			if got := configuredGoLoaderTimeout(); got != test.want {
				t.Fatalf("timeout = %s, want %s", got, test.want)
			}
		})
	}
}

// goLoaderTestModules discovers and parses every go.mod under root the same
// way the scanner does, so loader tests see the same module identities.
func goLoaderTestModules(t *testing.T, root string) []Module {
	t.Helper()
	manifests, _, diagnostics, err := findManifests(root, nil)
	if err != nil {
		t.Fatalf("findManifests() error = %v", err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("findManifests diagnostics = %+v", diagnostics)
	}
	modules := make([]Module, 0, len(manifests))
	for _, manifest := range manifests {
		module, parseDiagnostics := parseGoMod(manifest, root)
		if len(parseDiagnostics) != 0 {
			t.Fatalf("parseGoMod(%s) diagnostics = %+v", manifest, parseDiagnostics)
		}
		modules = append(modules, module)
	}
	sort.Slice(modules, func(left, right int) bool { return modules[left].RelativeDir < modules[right].RelativeDir })
	return modules
}

func goLoaderTestModule(t *testing.T, modules []Module, relativeDir string) Module {
	t.Helper()
	for _, module := range modules {
		if module.RelativeDir == relativeDir {
			return module
		}
	}
	t.Fatalf("module %q was not discovered in %+v", relativeDir, modules)
	return Module{}
}

func goLoaderTestFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := canonicalTestRoot(t, t.TempDir())
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		writeTestFile(t, filepath.Join(root, filepath.FromSlash(path)), files[path])
	}
	return root
}

func goLoaderTestSession(t *testing.T, root, buildCache string) *goLoaderSession {
	t.Helper()
	session, err := openGoLoaderSession(root, buildCache, nil, goPackagesLoadTimeout)
	if err != nil {
		t.Skipf("constrained Go environment unavailable: %v", err)
	}
	t.Cleanup(session.close)
	return session
}

func goLoaderTargetIDs(result goLoaderResult) []string {
	ids := make([]string, 0, len(result.Targets))
	for _, target := range result.Targets {
		ids = append(ids, target.ID)
	}
	return ids
}

func goLoaderReferenceIDs(result goLoaderResult, origin string) []string {
	ids := make([]string, 0)
	for _, reference := range result.References {
		if origin == "" || reference.Origin == origin {
			ids = append(ids, reference.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func goLoaderDiagnosticSummary(diagnostics []Diagnostic) string {
	lines := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		lines = append(lines, diagnostic.Code+": "+diagnostic.Message)
	}
	return strings.Join(lines, "\n")
}

// goLoaderProgramCounts walks the import graph of an SSA input the way the SSA
// builder does and reports how many packages carry syntax and how many files
// were parsed. It is the "inputs" side of the memory/inputs comparison.
func goLoaderProgramCounts(roots []*packages.Package) (loaded, syntax, files int) {
	packages.Visit(roots, nil, func(pkg *packages.Package) {
		if pkg == nil {
			return
		}
		loaded++
		if len(pkg.Syntax) > 0 {
			syntax++
			files += len(pkg.Syntax)
		}
	})
	return loaded, syntax, files
}

// goLoaderHash1 is the dirhash.Hash1 algorithm used by go.sum: it avoids a
// direct golang.org/x/mod dependency in the worker module.
func goLoaderHash1(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	summary := sha256.New()
	for _, name := range names {
		digest := sha256.Sum256(files[name])
		fmt.Fprintf(summary, "%x  %s\n", digest, name)
	}
	return "h1:" + base64.StdEncoding.EncodeToString(summary.Sum(nil))
}

// goLoaderWriteModuleCache materialises one module version in the
// GOPROXY=off download cache layout so the constrained Go command can resolve
// an external dependency without network access. It returns the go.sum lines
// the requiring module must carry under GOFLAGS=-mod=readonly.
func goLoaderWriteModuleCache(t *testing.T, cacheRoot, modulePath, version string, files map[string]string) string {
	t.Helper()
	prefix := modulePath + "@" + version + "/"
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	zipFiles := map[string][]byte{}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry, err := writer.Create(prefix + name)
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if _, err := entry.Write([]byte(files[name])); err != nil {
			t.Fatalf("write zip entry: %v", err)
		}
		zipFiles[prefix+name] = []byte(files[name])
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	zipHash := goLoaderHash1(zipFiles)
	modHash := goLoaderHash1(map[string][]byte{"go.mod": []byte(files["go.mod"])})
	downloadDir := filepath.Join(cacheRoot, "cache", "download", filepath.FromSlash(modulePath), "@v")
	writeTestFile(t, filepath.Join(downloadDir, version+".mod"), files["go.mod"])
	writeTestFile(t, filepath.Join(downloadDir, version+".info"), `{"Version":"`+version+`","Time":"2024-01-01T00:00:00Z"}`)
	writeTestFile(t, filepath.Join(downloadDir, version+".ziphash"), zipHash)
	writeTestFile(t, filepath.Join(downloadDir, "list"), version+"\n")
	if err := os.WriteFile(filepath.Join(downloadDir, version+".zip"), buffer.Bytes(), 0o644); err != nil {
		t.Fatalf("write module zip: %v", err)
	}
	return modulePath + " " + version + " " + zipHash + "\n" + modulePath + " " + version + "/go.mod " + modHash + "\n"
}

// goLoaderIsolatedModuleCache points the constrained Go command at a private
// module cache so tests neither depend on nor mutate the developer's cache.
func goLoaderIsolatedModuleCache(t *testing.T) string {
	t.Helper()
	cacheRoot := filepath.Join(t.TempDir(), "module-cache")
	if err := os.MkdirAll(cacheRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	cacheRoot = canonicalTestRoot(t, cacheRoot)
	t.Setenv("GOMODCACHE", cacheRoot)
	t.Setenv("GOPATH", filepath.Join(t.TempDir(), "isolated-gopath"))
	// The Go command extracts modules read-only; make the tree writable again
	// so TempDir cleanup can remove it.
	t.Cleanup(func() { goLoaderMakeWritable(t, cacheRoot) })
	return cacheRoot
}

func goLoaderMakeWritable(t *testing.T, root string) {
	t.Helper()
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			_ = os.Chmod(path, 0o755)
		} else {
			_ = os.Chmod(path, 0o644)
		}
		return nil
	})
}

const goLoaderBasicModule = "example.com/basic"

func goLoaderBasicFixture(t *testing.T) string {
	t.Helper()
	return goLoaderTestFixture(t, map[string]string{
		"go.mod": "module " + goLoaderBasicModule + "\n\ngo 1.26.1\n",
		"shape/shape.go": `package shape

type Shape interface{ Area() int }

type Square struct{ Side int }

func (s Square) Area() int { return s.Side * s.Side }

type Circle struct{ Radius int }

func (c *Circle) Area() int { return 3 * c.Radius * c.Radius }

func Maker() func() int { return func() int { return 42 } }

func New(side int) Shape { return Square{Side: side} }
`,
		"use/use.go": `package use

import (
	"fmt"

	"example.com/basic/shape"
)

type Local struct{}

func (Local) Area() int { return 1 }

func Total(shapes ...shape.Shape) int {
	total := 0
	for _, s := range shapes {
		total += s.Area()
	}
	return total
}

func Describe() string {
	return fmt.Sprintf("%d %d", Total(shape.New(2), Local{}), shape.Maker()())
}
`,
		"use/use_internal_test.go": `package use

import "testing"

type testShape struct{}

func (testShape) Area() int { return 7 }

func TestTotal(t *testing.T) {
	if Total(testShape{}) != 7 {
		t.Fatal("unexpected total")
	}
}
`,
		"use/use_external_test.go": `package use_test

import (
	"testing"

	"example.com/basic/shape"
	"example.com/basic/use"
)

func TestDescribe(t *testing.T) {
	if use.Total(shape.Square{Side: 1}) != 1 || use.Describe() == "" {
		t.Fatal("unexpected")
	}
}
`,
		"cmd/app/main.go": `package main

import (
	"fmt"

	"example.com/basic/use"
)

func main() { fmt.Println(use.Describe()) }
`,
	})
}

func TestGoLoaderPackageScopeLoadsTargetsFromSourceAndDependenciesFromExportData(t *testing.T) {
	root := goLoaderBasicFixture(t)
	modules := goLoaderTestModules(t, root)
	module := goLoaderTestModule(t, modules, ".")
	session := goLoaderTestSession(t, root, "")
	load := session.loader
	exportSeen := false
	session.loader = func(config *packages.Config, patterns ...string) ([]*packages.Package, error) {
		wantFlags := []string{"-tags=depgraph_fixture"}
		if config.Mode == goLoaderExportMode {
			exportSeen = true
			wantFlags = append(wantFlags, "-gcflags=all=-N -l")
		}
		if strings.Join(config.BuildFlags, "|") != strings.Join(wantFlags, "|") {
			t.Fatalf("load mode %v flags = %v, want %v", config.Mode, config.BuildFlags, wantFlags)
		}
		return load(config, patterns...)
	}

	result := session.loadPackageScope(goLoaderScope{
		Module: module, Modules: modules, Targets: []goLoaderTargetSpec{{Dir: "use", PkgPath: goLoaderBasicModule + "/use"}},
		Tags: []string{"depgraph_fixture"},
	}, nil)
	if result.Status != "loaded" {
		t.Fatalf("status = %q, diagnostics:\n%s", result.Status, goLoaderDiagnosticSummary(result.Diagnostics))
	}
	if !exportSeen {
		t.Fatal("the fixture did not exercise the dependency export-data load")
	}
	wantTargets := []string{
		goLoaderBasicModule + "/use",
		goLoaderBasicModule + "/use [" + goLoaderBasicModule + "/use.test]",
		goLoaderBasicModule + "/use_test [" + goLoaderBasicModule + "/use.test]",
	}
	if got := goLoaderTargetIDs(result); strings.Join(got, "|") != strings.Join(wantTargets, "|") {
		t.Fatalf("target variants = %v, want %v", got, wantTargets)
	}
	metrics := result.Metrics
	if metrics.TargetPackages != 3 || metrics.SyntaxPackages != 3 {
		t.Fatalf("syntax packages must equal target packages: %+v", metrics)
	}
	// use.go, {use.go, use_internal_test.go}, use_external_test.go
	if metrics.TargetFiles != 1+2+1 || metrics.ParsedFiles != metrics.TargetFiles || metrics.TargetBytes <= 0 {
		t.Fatalf("target file accounting = %+v", metrics)
	}
	if metrics.SelfPeakRSSBytes <= 0 || metrics.ChildMaxRSSBytes <= 0 {
		t.Fatalf("resident-set evidence was not measured on this platform: %+v", metrics)
	}
	if metrics.LoadedPackages <= metrics.TargetPackages {
		t.Fatalf("export-data dependencies were not attached to the program: %+v", metrics)
	}
	if metrics.ReferencesSource != 0 || metrics.ReferencesExport == 0 || metrics.ChildProcesses != 2 {
		t.Fatalf("reference accounting = %+v", metrics)
	}
	if got := goLoaderReferenceIDs(result, goLoaderOriginInRepo); strings.Join(got, "|") != goLoaderBasicModule+"/shape" {
		t.Fatalf("in-repo references = %v, want only shape", got)
	}
	if got := goLoaderReferenceIDs(result, goLoaderOriginStandard); !containsString(got, "fmt") || !containsString(got, "testing") {
		t.Fatalf("standard-library references = %v, want fmt and testing", got)
	}
	if len(result.ReferencePackages) != 1 || result.ReferencePackages[0].PkgPath != goLoaderBasicModule+"/shape" ||
		result.ReferencePackages[0].ModuleRelativeDir != "." || result.ReferencePackages[0].Types == nil {
		t.Fatalf("reference packages = %+v", result.ReferencePackages)
	}
	if result.SSAInput == nil || result.SSAInput.ProgramScope != goSSAProgramScopePackage || len(result.SSAInput.Roots) != 3 {
		t.Fatalf("SSA input = %+v", result.SSAInput)
	}
	if metrics.Witness == "" || result.ReferenceFingerprint.Fingerprint == "" || result.ReferenceFingerprint.PackageCount != 1 {
		t.Fatalf("witness/fingerprint = %+v %+v", metrics.Witness, result.ReferenceFingerprint)
	}
	for _, typed := range result.TypedPackages {
		if typed.Types == nil || typed.TypesInfo == nil || typed.TypesSizes == nil || typed.FileSet == nil || typed.SSAInput != result.SSAInput {
			t.Fatalf("typed package %q is incomplete: %+v", typed.ID, typed)
		}
		if typed.ModuleRelativeDir != "." || typed.ModulePath != goLoaderBasicModule {
			t.Fatalf("typed package %q has wrong module identity: %+v", typed.ID, typed)
		}
	}
	// Dependencies must be declaration-only: no syntax anywhere except targets.
	for _, target := range result.Targets {
		for path, imported := range target.Imports {
			if _, isTarget := map[string]bool{wantTargets[0]: true, wantTargets[1]: true, wantTargets[2]: true}[imported.ID]; isTarget {
				continue
			}
			if len(imported.Syntax) != 0 || imported.TypesInfo != nil {
				t.Fatalf("dependency %q of %q carries syntax", path, target.ID)
			}
			if imported.Types == nil {
				t.Fatalf("dependency %q of %q has no types", path, target.ID)
			}
		}
	}
}

// goLoaderIdentityFixture is the "ident" shape of the plan: an app module that
// replaces a dependency with an in-repo directory, two same-path modules in
// different directories (only one of which is the replacement target), and a
// dependency package with an interface, a closure and a constructor.
func goLoaderIdentityFixture(t *testing.T) string {
	t.Helper()
	return goLoaderTestFixture(t, map[string]string{
		"app/go.mod": `module example.com/app

go 1.26.1

require (
	example.com/dep v0.0.0
	example.com/twin v0.0.0
)

replace example.com/dep => ../dep

replace example.com/twin => ../twins/a
`,
		"app/use/use.go": `package use

import (
	"example.com/dep/shape"
	"example.com/twin/lib"
)

type Local struct{}

func (Local) Area() int { return 1 }

func Total(shapes ...shape.Shape) int {
	total := 0
	for _, s := range shapes {
		total += s.Area()
	}
	return total
}

func Describe() int {
	return Total(shape.New(2), Local{}) + shape.Maker()() + lib.Make().A
}
`,
		"app/use/use_external_test.go": `package use_test

import (
	"testing"

	"example.com/app/use"
	"example.com/dep/shape"
)

func TestDescribe(t *testing.T) {
	if use.Total(shape.Square{Side: 1}) != 1 || use.Describe() == 0 {
		t.Fatal("unexpected")
	}
}
`,
		"dep/go.mod": "module example.com/dep\n\ngo 1.26.1\n",
		"dep/shape/shape.go": `package shape

type Shape interface{ Area() int }

type Square struct{ Side int }

func (s Square) Area() int { return s.Side * s.Side }

func Maker() func() int { return func() int { return 42 } }

func New(side int) Shape { return Square{Side: side} }
`,
		"twins/a/go.mod":     "module example.com/twin\n\ngo 1.26.1\n",
		"twins/a/lib/lib.go": "package lib\n\ntype Value struct{ A int }\n\nfunc Make() Value { return Value{A: 1} }\n",
		"twins/b/go.mod":     "module example.com/twin\n\ngo 1.26.1\n",
		"twins/b/lib/lib.go": "package lib\n\ntype Value struct{ B string }\n\nfunc Make() Value { return Value{B: \"b\"} }\n",
	})
}

// TestGoLoaderScopeTable drives the loader over every fixture shape with one
// table: which variants become targets, which in-repo packages become
// references (and from which source), and which scope errors fail closed.
func TestGoLoaderScopeTable(t *testing.T) {
	fixtures := map[string]func(*testing.T) string{
		"basic":    goLoaderBasicFixture,
		"identity": goLoaderIdentityFixture,
		"cycle":    goLoaderTestCycleFixture,
	}
	cases := []struct {
		name            string
		fixture         string
		module          string
		targets         []goLoaderTargetSpec
		wantTargets     []string
		wantInRepo      map[string]string // reference ID -> source
		wantFingerprint int               // in-repo packages in the reference fingerprint
		wantCode        string            // first diagnostic code when the load fails closed
	}{
		{
			name: "library with both test variants", fixture: "basic", module: ".",
			targets: []goLoaderTargetSpec{{Dir: "use"}},
			wantTargets: []string{
				goLoaderBasicModule + "/use",
				goLoaderBasicModule + "/use [" + goLoaderBasicModule + "/use.test]",
				goLoaderBasicModule + "/use_test [" + goLoaderBasicModule + "/use.test]",
			},
			wantInRepo: map[string]string{goLoaderBasicModule + "/shape": goLoaderReferenceExport}, wantFingerprint: 1,
		},
		{
			// Indirect in-repo dependencies (shape via use) are references too:
			// they are in the program and in the fingerprint closure.
			name: "main package imports the library from export data", fixture: "basic", module: ".",
			targets:     []goLoaderTargetSpec{{Dir: "cmd/app", PkgPath: goLoaderBasicModule + "/cmd/app"}},
			wantTargets: []string{goLoaderBasicModule + "/cmd/app"},
			wantInRepo:  map[string]string{goLoaderBasicModule + "/use": goLoaderReferenceExport, goLoaderBasicModule + "/shape": goLoaderReferenceExport}, wantFingerprint: 2,
		},
		{
			name: "two packages in one scope reference each other in process", fixture: "basic", module: ".",
			targets: []goLoaderTargetSpec{{Dir: "use"}, {Dir: "shape"}},
			wantTargets: []string{
				goLoaderBasicModule + "/shape",
				goLoaderBasicModule + "/use",
				goLoaderBasicModule + "/use [" + goLoaderBasicModule + "/use.test]",
				goLoaderBasicModule + "/use_test [" + goLoaderBasicModule + "/use.test]",
			},
			wantInRepo: map[string]string{}, wantFingerprint: 0,
		},
		{
			name: "leaf package has no in-repo references", fixture: "basic", module: ".",
			targets:     []goLoaderTargetSpec{{Dir: "shape"}},
			wantTargets: []string{goLoaderBasicModule + "/shape"},
			wantInRepo:  map[string]string{}, wantFingerprint: 0,
		},
		{
			name: "local replace and same-path module resolve by directory", fixture: "identity", module: "app",
			targets:     []goLoaderTargetSpec{{Dir: "app/use"}},
			wantTargets: []string{"example.com/app/use", "example.com/app/use_test [example.com/app/use.test]"},
			wantInRepo:  map[string]string{"example.com/dep/shape": goLoaderReferenceExport, "example.com/twin/lib": goLoaderReferenceExport}, wantFingerprint: 2,
		},
		{
			name: "same-path twin a is its own scope", fixture: "identity", module: "twins/a",
			targets: []goLoaderTargetSpec{{Dir: "twins/a/lib"}}, wantTargets: []string{"example.com/twin/lib"}, wantInRepo: map[string]string{},
		},
		{
			name: "same-path twin b is its own scope", fixture: "identity", module: "twins/b",
			targets: []goLoaderTargetSpec{{Dir: "twins/b/lib"}}, wantTargets: []string{"example.com/twin/lib"}, wantInRepo: map[string]string{},
		},
		{
			name: "test-induced recompile falls back to source declarations", fixture: "cycle", module: ".",
			targets: []goLoaderTargetSpec{{Dir: "p"}},
			wantTargets: []string{
				"example.com/cycle/p",
				"example.com/cycle/p [example.com/cycle/p.test]",
				"example.com/cycle/p_test [example.com/cycle/p.test]",
			},
			wantInRepo: map[string]string{"example.com/cycle/q [example.com/cycle/p.test]": goLoaderReferenceSource}, wantFingerprint: 1,
		},
		{
			// "q [p.test]" is never a listing root, so like the module-whole-program
			// typed set it is not a target even when q is; it stays a
			// declaration-only source reference of p's external test.
			name: "cycle members in one scope keep the recompiled variant as a reference", fixture: "cycle", module: ".",
			targets: []goLoaderTargetSpec{{Dir: "p"}, {Dir: "q"}},
			wantTargets: []string{
				"example.com/cycle/p",
				"example.com/cycle/q",
				"example.com/cycle/p [example.com/cycle/p.test]",
				"example.com/cycle/p_test [example.com/cycle/p.test]",
			},
			wantInRepo: map[string]string{"example.com/cycle/q [example.com/cycle/p.test]": goLoaderReferenceSource}, wantFingerprint: 1,
		},
		{
			name: "missing target directory fails closed", fixture: "basic", module: ".",
			targets: []goLoaderTargetSpec{{Dir: "nope"}}, wantCode: "go_loader_target_missing",
		},
		{
			name: "target outside the scope module fails closed", fixture: "identity", module: "app",
			targets: []goLoaderTargetSpec{{Dir: "dep/shape"}}, wantCode: "go_loader_scope_invalid",
		},
		{
			name: "absolute target directory fails closed", fixture: "basic", module: ".",
			targets: []goLoaderTargetSpec{{Dir: "/use"}}, wantCode: "go_loader_scope_invalid",
		},
		{
			name: "duplicate target directory fails closed", fixture: "basic", module: ".",
			targets: []goLoaderTargetSpec{{Dir: "use"}, {Dir: "./use"}}, wantCode: "go_loader_scope_invalid",
		},
		{
			name: "package path mismatch fails closed", fixture: "basic", module: ".",
			targets: []goLoaderTargetSpec{{Dir: "use", PkgPath: goLoaderBasicModule + "/other"}}, wantCode: "go_loader_target_mismatch",
		},
		{
			name: "empty scope fails closed", fixture: "basic", module: ".", wantCode: "go_loader_scope_invalid",
		},
	}
	roots := map[string]string{}
	sessions := map[string]*goLoaderSession{}
	moduleSets := map[string][]Module{}
	for name, fixture := range fixtures {
		roots[name] = fixture(t)
		moduleSets[name] = goLoaderTestModules(t, roots[name])
		sessions[name] = goLoaderTestSession(t, roots[name], "")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			modules := moduleSets[tc.fixture]
			result := sessions[tc.fixture].loadPackageScope(goLoaderScope{
				Module: goLoaderTestModule(t, modules, tc.module), Modules: modules, Targets: tc.targets,
			}, nil)
			if tc.wantCode != "" {
				if result.Status != "fallback" || len(result.TypedPackages) != 0 || result.SSAInput != nil {
					t.Fatalf("status = %q typed = %d, want a closed fallback", result.Status, len(result.TypedPackages))
				}
				if len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != tc.wantCode {
					t.Fatalf("diagnostics = %s, want first code %s", goLoaderDiagnosticSummary(result.Diagnostics), tc.wantCode)
				}
				return
			}
			if result.Status != "loaded" {
				t.Fatalf("status = %q:\n%s", result.Status, goLoaderDiagnosticSummary(result.Diagnostics))
			}
			if got := goLoaderTargetIDs(result); strings.Join(got, "|") != strings.Join(tc.wantTargets, "|") {
				t.Fatalf("targets = %v, want %v", got, tc.wantTargets)
			}
			gotInRepo := map[string]string{}
			for _, reference := range result.References {
				if reference.Origin == goLoaderOriginInRepo {
					gotInRepo[reference.ID] = reference.Source
				}
			}
			if len(gotInRepo) != len(tc.wantInRepo) {
				t.Fatalf("in-repo references = %v, want %v", gotInRepo, tc.wantInRepo)
			}
			for id, source := range tc.wantInRepo {
				if gotInRepo[id] != source {
					t.Fatalf("in-repo reference %s source = %q, want %q (all %v)", id, gotInRepo[id], source, gotInRepo)
				}
			}
			if len(result.ReferencePackages) != len(tc.wantInRepo) || result.ReferenceFingerprint.PackageCount != tc.wantFingerprint {
				t.Fatalf("reference packages = %d fingerprint packages = %d, want %d/%d", len(result.ReferencePackages), result.ReferenceFingerprint.PackageCount, len(tc.wantInRepo), tc.wantFingerprint)
			}
			metrics := result.Metrics
			if metrics.TargetPackages != len(tc.wantTargets) || metrics.SyntaxPackages != metrics.TargetPackages {
				t.Fatalf("only targets may carry syntax: %+v", metrics)
			}
			if metrics.LoadedPackages < metrics.SyntaxPackages {
				t.Fatalf("program graph is smaller than its targets: %+v", metrics)
			}
			wantChildProcesses := 2
			if metrics.LoadedPackages == metrics.SyntaxPackages {
				// A scope without any dependency skips the export load entirely.
				wantChildProcesses = 1
			}
			if metrics.ChildProcesses != wantChildProcesses {
				t.Fatalf("child processes = %d, want %d: %+v", metrics.ChildProcesses, wantChildProcesses, metrics)
			}
			// One identity, one universe: every import of every target resolves
			// to the same *packages.Package for the same ID across the program.
			byID := map[string]*packages.Package{}
			packages.Visit(result.Targets, nil, func(pkg *packages.Package) {
				if existing, seen := byID[pkg.ID]; seen && existing != pkg {
					t.Fatalf("package %q appears as two distinct universes in one program", pkg.ID)
				}
				byID[pkg.ID] = pkg
			})
			if result.SSAInput == nil || result.SSAInput.ProgramScope != goSSAProgramScopePackage {
				t.Fatalf("SSA input = %+v", result.SSAInput)
			}
		})
	}
}

func TestGoLoaderPreservesIdentityAcrossLocalReplaceAndSameNameModules(t *testing.T) {
	root := goLoaderIdentityFixture(t)
	modules := goLoaderTestModules(t, root)
	session := goLoaderTestSession(t, root, "")

	app := session.loadPackageScope(goLoaderScope{
		Module: goLoaderTestModule(t, modules, "app"), Modules: modules,
		Targets: []goLoaderTargetSpec{{Dir: "app/use", PkgPath: "example.com/app/use"}},
	}, nil)
	if app.Status != "loaded" {
		t.Fatalf("app status = %q, diagnostics:\n%s", app.Status, goLoaderDiagnosticSummary(app.Diagnostics))
	}
	wantTargets := []string{"example.com/app/use", "example.com/app/use_test [example.com/app/use.test]"}
	if got := goLoaderTargetIDs(app); strings.Join(got, "|") != strings.Join(wantTargets, "|") {
		t.Fatalf("app target variants = %v, want %v", got, wantTargets)
	}
	// Both replaced modules resolve to their in-repo directories: the reference
	// identity is the module directory relative to the root, never the module
	// path alone, so twins/b (same module path, not the replacement target)
	// never appears.
	byPath := map[string]goReferencePackage{}
	for _, reference := range app.ReferencePackages {
		byPath[reference.PkgPath] = reference
	}
	if len(byPath) != 2 {
		t.Fatalf("in-repo reference packages = %+v, want dep/shape and twins/a/lib", app.ReferencePackages)
	}
	if shape := byPath["example.com/dep/shape"]; shape.ModuleRelativeDir != "dep" || shape.ModulePath != "example.com/dep" || shape.Source != goLoaderReferenceExport || shape.Types == nil {
		t.Fatalf("replaced dependency reference = %+v", shape)
	}
	if lib := byPath["example.com/twin/lib"]; lib.ModuleRelativeDir != "twins/a" || lib.ModulePath != "example.com/twin" || lib.Source != goLoaderReferenceExport {
		t.Fatalf("same-path module reference = %+v", lib)
	}
	libValue, _ := byPath["example.com/twin/lib"].Types.Scope().Lookup("Value").(*types.TypeName)
	if libValue == nil {
		t.Fatal("twin/lib Value type missing from export data")
	}
	if fields := libValue.Type().Underlying().(*types.Struct); fields.NumFields() != 1 || fields.Field(0).Name() != "A" {
		t.Fatalf("app resolved example.com/twin/lib to the wrong module instance: %v", libValue.Type().Underlying())
	}
	for _, reference := range app.References {
		if reference.Origin == goLoaderOriginInRepo && reference.ModuleRelativeDir == "twins/b" {
			t.Fatalf("twins/b leaked into the app load: %+v", reference)
		}
	}
	if app.Metrics.ReferencesInRepo != 2 || app.Metrics.ReferencesSource != 0 {
		t.Fatalf("reference metrics = %+v", app.Metrics)
	}
	// The external test variant imports the checked in-package variant, not a
	// second universe of the same package.
	external := app.Targets[1]
	if imported := external.Imports["example.com/app/use"]; imported != app.Targets[0] || imported.Types != app.Targets[0].Types {
		t.Fatalf("external test imported %v, want the checked in-package variant", imported)
	}
	if imported := external.Imports["example.com/dep/shape"]; imported != app.Targets[0].Imports["example.com/dep/shape"] {
		t.Fatal("target variants resolved the same dependency to different packages")
	}
	// The reference fingerprint covers exactly the transitive in-repo closure:
	// dep/shape and twins/a/lib, but not twins/b.
	if app.ReferenceFingerprint.PackageCount != 2 || app.ReferenceFingerprint.FileCount != 2 || len(app.ReferenceFingerprint.Reasons) != 0 {
		t.Fatalf("reference fingerprint = %+v", app.ReferenceFingerprint)
	}

	// Same-path modules keep distinct identities when loaded as their own
	// scopes: same PkgPath and Module.Path, different directory and types.
	twinA := session.loadPackageScope(goLoaderScope{
		Module: goLoaderTestModule(t, modules, "twins/a"), Modules: modules,
		Targets: []goLoaderTargetSpec{{Dir: "twins/a/lib"}},
	}, nil)
	twinB := session.loadPackageScope(goLoaderScope{
		Module: goLoaderTestModule(t, modules, "twins/b"), Modules: modules,
		Targets: []goLoaderTargetSpec{{Dir: "twins/b/lib"}},
	}, nil)
	if twinA.Status != "loaded" || twinB.Status != "loaded" {
		t.Fatalf("twin status = %q/%q:\n%s\n%s", twinA.Status, twinB.Status, goLoaderDiagnosticSummary(twinA.Diagnostics), goLoaderDiagnosticSummary(twinB.Diagnostics))
	}
	if twinA.Targets[0].PkgPath != twinB.Targets[0].PkgPath || twinA.Targets[0].Module.Path != twinB.Targets[0].Module.Path {
		t.Fatalf("twins should share package and module paths: %+v %+v", twinA.Targets[0], twinB.Targets[0])
	}
	if twinA.TypedPackages[0].ModuleRelativeDir != "twins/a" || twinB.TypedPackages[0].ModuleRelativeDir != "twins/b" {
		t.Fatalf("twins lost their module directory identity: %q %q", twinA.TypedPackages[0].ModuleRelativeDir, twinB.TypedPackages[0].ModuleRelativeDir)
	}
	if twinA.Targets[0].Types == twinB.Targets[0].Types {
		t.Fatal("twins share one go/types universe")
	}
	if twinA.Metrics.Witness == twinB.Metrics.Witness {
		t.Fatal("twin witnesses collide although their files differ")
	}
}

func TestGoLoaderReferenceFingerprintTracksInRepoDependencySources(t *testing.T) {
	root := goLoaderIdentityFixture(t)
	modules := goLoaderTestModules(t, root)
	scope := goLoaderScope{
		Module: goLoaderTestModule(t, modules, "app"), Modules: modules,
		Targets: []goLoaderTargetSpec{{Dir: "app/use"}},
	}
	load := func() goLoaderResult {
		session := goLoaderTestSession(t, root, "")
		result := session.loadPackageScope(scope, nil)
		if result.Status != "loaded" {
			t.Fatalf("status = %q:\n%s", result.Status, goLoaderDiagnosticSummary(result.Diagnostics))
		}
		return result
	}
	before := load()
	same := load()
	if before.ReferenceFingerprint.Fingerprint != same.ReferenceFingerprint.Fingerprint || before.Metrics.Witness != same.Metrics.Witness {
		t.Fatalf("fingerprint/witness are not deterministic: %+v %+v", before.ReferenceFingerprint, same.ReferenceFingerprint)
	}
	// twins/b is not in the closure: editing it must not invalidate app/use.
	writeTestFile(t, filepath.Join(root, "twins", "b", "lib", "lib.go"), "package lib\n\ntype Value struct{ B string; C int }\n\nfunc Make() Value { return Value{} }\n")
	unrelated := load()
	if unrelated.ReferenceFingerprint.Fingerprint != before.ReferenceFingerprint.Fingerprint {
		t.Fatal("editing an unrelated same-path module changed the reference fingerprint")
	}
	// dep/shape is in the closure: a body-only edit still changes the source
	// digest and therefore the fingerprint, while the witness (which lists
	// files, not contents) is unchanged.
	writeTestFile(t, filepath.Join(root, "dep", "shape", "shape.go"), strings.Replace(mustReadTestFile(t, filepath.Join(root, "dep", "shape", "shape.go")), "return 42", "return 43", 1))
	changed := load()
	if changed.ReferenceFingerprint.Fingerprint == before.ReferenceFingerprint.Fingerprint {
		t.Fatal("editing an in-repo dependency did not change the reference fingerprint")
	}
	if changed.Metrics.Witness != before.Metrics.Witness {
		t.Fatal("the witness must describe loaded inputs, not their contents")
	}
}

func mustReadTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// goLoaderTestCycleFixture: p's external test imports q, and q imports p. The
// test binary therefore needs q recompiled against p's internal-test variant
// ("q [p.test]"), which no export data can provide.
func goLoaderTestCycleFixture(t *testing.T) string {
	t.Helper()
	return goLoaderTestFixture(t, map[string]string{
		"go.mod":               "module example.com/cycle\n\ngo 1.26.1\n",
		"p/p.go":               "package p\n\nfunc P() int { return 1 }\n",
		"p/p_internal_test.go": "package p\n\nimport \"testing\"\n\nfunc hidden() int { return 2 }\n\nfunc TestP(t *testing.T) {\n\tif P()+hidden() != 3 {\n\t\tt.Fatal(\"p\")\n\t}\n}\n",
		"p/p_external_test.go": "package p_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/cycle/p\"\n\t\"example.com/cycle/q\"\n)\n\nfunc TestQ(t *testing.T) {\n\tif q.Q() != p.P() {\n\t\tt.Fatal(\"q\")\n\t}\n}\n",
		"q/q.go":               "package q\n\nimport \"example.com/cycle/p\"\n\nfunc Q() int { return p.P() }\n",
	})
}

func TestGoLoaderTestInducedRecompileFallsBackToSourceDeclarations(t *testing.T) {
	root := goLoaderTestCycleFixture(t)
	modules := goLoaderTestModules(t, root)
	module := goLoaderTestModule(t, modules, ".")
	session := goLoaderTestSession(t, root, "")

	result := session.loadPackageScope(goLoaderScope{
		Module: module, Modules: modules, Targets: []goLoaderTargetSpec{{Dir: "p"}},
	}, nil)
	if result.Status != "loaded" {
		t.Fatalf("status = %q:\n%s", result.Status, goLoaderDiagnosticSummary(result.Diagnostics))
	}
	wantTargets := []string{
		"example.com/cycle/p",
		"example.com/cycle/p [example.com/cycle/p.test]",
		"example.com/cycle/p_test [example.com/cycle/p.test]",
	}
	if got := goLoaderTargetIDs(result); strings.Join(got, "|") != strings.Join(wantTargets, "|") {
		t.Fatalf("target variants = %v, want %v", got, wantTargets)
	}
	recompiled := "example.com/cycle/q [example.com/cycle/p.test]"
	if got := goLoaderReferenceIDs(result, goLoaderOriginInRepo); strings.Join(got, "|") != recompiled {
		t.Fatalf("in-repo references = %v, want only the recompiled variant", got)
	}
	if result.Metrics.ReferencesSource != 1 || result.Metrics.ParsedFiles != result.Metrics.TargetFiles+1 {
		t.Fatalf("source fallback accounting = %+v", result.Metrics)
	}
	if result.Metrics.SyntaxPackages != result.Metrics.TargetPackages {
		t.Fatalf("the recompiled dependency must not carry syntax: %+v", result.Metrics)
	}
	external := result.Targets[2]
	variant := external.Imports["example.com/cycle/q"]
	if variant == nil || variant.ID != recompiled || variant.Types == nil || len(variant.Syntax) != 0 || variant.TypesInfo != nil {
		t.Fatalf("recompiled dependency = %+v", variant)
	}
	// Identity: the recompiled q imports the in-package test variant of p that
	// this load checked, so p's types are one universe across the program.
	if imported := variant.Imports["example.com/cycle/p"]; imported != result.Targets[1] {
		t.Fatalf("q [p.test] imported %v, want the checked p [p.test] variant", imported)
	}
	if imported := external.Imports["example.com/cycle/p"]; imported != result.Targets[1] {
		t.Fatalf("p_test imported %v, want the checked p [p.test] variant", imported)
	}
	if len(result.ReferencePackages) != 1 || result.ReferencePackages[0].Source != goLoaderReferenceSource || result.ReferencePackages[0].ID != recompiled {
		t.Fatalf("reference packages = %+v", result.ReferencePackages)
	}
	if qFunc := result.ReferencePackages[0].Types.Scope().Lookup("Q"); qFunc == nil {
		t.Fatal("recompiled q lost its declarations")
	}
	// The recompiled variant is in-repo and part of the fingerprint closure.
	if result.ReferenceFingerprint.PackageCount != 1 || result.ReferenceFingerprint.FileCount != 1 {
		t.Fatalf("reference fingerprint = %+v", result.ReferenceFingerprint)
	}
}

func TestGoLoaderPackageScopeShrinksLoadedInputVersusModuleWholeProgram(t *testing.T) {
	root := goLoaderBasicFixture(t)
	modules := goLoaderTestModules(t, root)
	module := goLoaderTestModule(t, modules, ".")

	whole := loadGoPackagesInventory(root, modules, WorkFile{}, nil)
	if whole.Status != "loaded" {
		t.Fatalf("module-whole-program status = %q: %+v", whole.Status, whole.Diagnostics)
	}
	var wholeRoots []*packages.Package
	seenInputs := map[*goSSAInput]bool{}
	for _, typed := range whole.TypedPackages {
		if typed.SSAInput != nil && !seenInputs[typed.SSAInput] {
			seenInputs[typed.SSAInput] = true
			wholeRoots = append(wholeRoots, typed.SSAInput.Roots...)
		}
	}
	wholeLoaded, wholeSyntax, wholeFiles := goLoaderProgramCounts(wholeRoots)

	session := goLoaderTestSession(t, root, "")
	scoped := session.loadPackageScope(goLoaderScope{
		Module: module, Modules: modules, Targets: []goLoaderTargetSpec{{Dir: "use"}},
	}, nil)
	if scoped.Status != "loaded" {
		t.Fatalf("package-scope status = %q:\n%s", scoped.Status, goLoaderDiagnosticSummary(scoped.Diagnostics))
	}
	scopedLoaded, scopedSyntax, scopedFiles := goLoaderProgramCounts(scoped.SSAInput.Roots)
	if scopedSyntax != scoped.Metrics.SyntaxPackages || scopedFiles != scoped.Metrics.ParsedFiles || scopedLoaded != scoped.Metrics.LoadedPackages {
		t.Fatalf("metrics disagree with the program graph: graph=(%d,%d,%d) metrics=%+v", scopedLoaded, scopedSyntax, scopedFiles, scoped.Metrics)
	}
	// Whole-program loading parses the standard library closure (fmt, testing,
	// runtime, ...) from source; the package scope parses only the targets.
	if scopedSyntax != 3 || wholeSyntax <= 3*scopedSyntax {
		t.Fatalf("syntax packages: package-scope=%d whole-program=%d", scopedSyntax, wholeSyntax)
	}
	if scopedFiles != 4 || wholeFiles <= 10*scopedFiles {
		t.Fatalf("parsed files: package-scope=%d whole-program=%d", scopedFiles, wholeFiles)
	}
	if scopedLoaded > wholeLoaded {
		t.Fatalf("package scope attached more packages (%d) than the whole program (%d)", scopedLoaded, wholeLoaded)
	}
	t.Logf("inputs comparison: package-scope loaded=%d syntax=%d parsed_files=%d target_bytes=%d self_rss=%d child_rss=%d; module-whole-program loaded=%d syntax=%d parsed_files=%d",
		scopedLoaded, scopedSyntax, scopedFiles, scoped.Metrics.TargetBytes, scoped.Metrics.SelfPeakRSSBytes, scoped.Metrics.ChildMaxRSSBytes, wholeLoaded, wholeSyntax, wholeFiles)
}

func TestGoLoaderBuildCacheIsConfinedAndSharedAcrossSessions(t *testing.T) {
	root := goLoaderBasicFixture(t)
	modules := goLoaderTestModules(t, root)
	module := goLoaderTestModule(t, modules, ".")
	for _, rejected := range []string{"relative/cache", filepath.Join(root, "inside-root"), filepath.Join(root, "..", filepath.Base(root), "nested")} {
		if _, err := openGoLoaderSession(root, rejected, nil, goPackagesLoadTimeout); err == nil || !strings.Contains(err.Error(), "build cache") {
			t.Fatalf("build cache %q was admitted: %v", rejected, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "inside-root")); !os.IsNotExist(err) {
		t.Fatal("a rejected build cache directory was created inside the scan root")
	}

	// The cache directory does not exist yet: the session creates it.
	shared := filepath.Join(canonicalTestRoot(t, t.TempDir()), "scan-build-cache")
	scope := goLoaderScope{Module: module, Modules: modules, Targets: []goLoaderTargetSpec{{Dir: "use"}}}

	first := goLoaderTestSession(t, root, shared)
	if got := lookupEnvironmentValue(first.commandEnvironment(""), "GOCACHE"); got != shared {
		t.Fatalf("session GOCACHE = %q, want %q", got, shared)
	}
	if !first.buildCache.Shared || first.buildCache.Reused {
		t.Fatalf("first session build cache state = %+v", first.buildCache)
	}
	cold := first.loadPackageScope(scope, nil)
	if cold.Status != "loaded" || !cold.Metrics.BuildCacheShared || cold.Metrics.BuildCacheReused {
		t.Fatalf("cold load = %q %+v:\n%s", cold.Status, cold.Metrics, goLoaderDiagnosticSummary(cold.Diagnostics))
	}
	first.close()
	if !goBuildCachePopulated(shared) {
		t.Fatal("the export-data load did not populate the shared build cache")
	}

	second := goLoaderTestSession(t, root, shared)
	if !second.buildCache.Reused {
		t.Fatalf("second session did not detect the populated cache: %+v", second.buildCache)
	}
	warm := second.loadPackageScope(scope, nil)
	if warm.Status != "loaded" || !warm.Metrics.BuildCacheReused {
		t.Fatalf("warm load = %q %+v", warm.Status, warm.Metrics)
	}
	if warm.Metrics.Witness != cold.Metrics.Witness || warm.ReferenceFingerprint.Fingerprint != cold.ReferenceFingerprint.Fingerprint {
		t.Fatal("cache reuse changed the loaded inputs")
	}
	properties := goLoaderProperties(&goLoaderReport{Mode: goLoaderModePackage, ProgramScope: goSSAProgramScopePackage, Metrics: warm.Metrics, ReferenceFingerprint: warm.ReferenceFingerprint})
	if properties["go_loader_build_cache"] != "scan-shared" || properties["go_loader_build_cache_reused"] != "true" {
		t.Fatalf("build cache properties = %+v", properties)
	}

	private := goLoaderTestSession(t, root, "")
	if private.buildCache.Shared || private.buildCache.Dir == "" || private.buildCache.Dir == shared {
		t.Fatalf("default session must keep an invocation-private GOCACHE: %+v", private.buildCache)
	}
	t.Logf("build cache: cold export_ms=%d child_rss=%d; warm export_ms=%d child_rss=%d", cold.Metrics.ExportMilliseconds, cold.Metrics.ChildMaxRSSBytes, warm.Metrics.ExportMilliseconds, warm.Metrics.ChildMaxRSSBytes)
}

func TestGoLoaderPropertiesExposeEvidenceForCore(t *testing.T) {
	root := goLoaderBasicFixture(t)
	modules := goLoaderTestModules(t, root)
	inventory := loadGoPackagesInventoryPackageScope(root, modules, []goLoaderTargetSpec{{Dir: "use"}}, nil, WorkFile{}, nil, "", nil)
	if inventory.Status != "loaded" || inventory.Loader == nil {
		t.Fatalf("inventory = %+v", inventory)
	}
	properties := inventoryProperties(inventory)
	want := map[string]string{
		"analysis_loader_mode":                    "package",
		"go_loader_program_scope":                 "package-with-declaration-deps",
		"go_loader_target_packages":               "3",
		"go_loader_syntax_packages":               "3",
		"go_loader_syntax_equals_targets":         "true",
		"go_loader_target_files":                  "4",
		"go_loader_parsed_files":                  "4",
		"go_loader_child_processes":               "2",
		"go_loader_child_process_target_compiled": "false",
		"go_loader_build_cache":                   "invocation-private",
		"go_loader_build_cache_reused":            "false",
		"go_loader_reference_packages_source":     "0",
		"go_loader_reference_packages_in_repo":    "1",
		"go_reference_fingerprint_schema":         goReferenceFingerprintSchema,
		"go_reference_fingerprint_packages":       "1",
		"go_loader_dependency_snapshot_source":    "module-wide-metadata-listing",
		"go_packages_status":                      "loaded",
	}
	for key, value := range want {
		if properties[key] != value {
			t.Fatalf("property %s = %q, want %q (all: %+v)", key, properties[key], value, properties)
		}
	}
	for _, key := range []string{"go_loader_loaded_packages", "go_loader_target_bytes", "go_loader_reference_packages_export", "go_loader_reference_packages_standard", "go_loader_peak_rss_bytes", "go_loader_child_max_rss_bytes", "go_loader_witness", "go_reference_fingerprint"} {
		if properties[key] == "" || properties[key] == "0" {
			t.Fatalf("property %s missing or zero: %+v", key, properties)
		}
	}
	for _, key := range []string{"go_loader_listing_ms", "go_loader_export_compile_ms", "go_loader_type_check_ms"} {
		if _, err := strconv.Atoi(properties[key]); err != nil {
			t.Fatalf("timing property %s = %q is not an integer", key, properties[key])
		}
	}
	if inventory.PackageCount != 3 || inventory.TestVariantCount != 2 || inventory.ActiveFileCount != 3 || len(inventory.ReferencePackages) != 1 {
		t.Fatalf("inventory counts = %+v", inventory)
	}
}

// goLoaderExternalFixture extends the basic module with an external module
// served from an isolated GOPROXY=off module cache.
func goLoaderExternalFixture(t *testing.T) (string, string) {
	t.Helper()
	cacheRoot := goLoaderIsolatedModuleCache(t)
	sums := goLoaderWriteModuleCache(t, cacheRoot, "example.com/extdep", "v1.0.0", map[string]string{
		"go.mod":       "module example.com/extdep\n\ngo 1.26.1\n",
		"text/text.go": "package text\n\nimport \"strings\"\n\nfunc Upper(value string) string { return strings.ToUpper(value) }\n",
	})
	root := goLoaderBasicFixture(t)
	writeTestFile(t, filepath.Join(root, "go.mod"), "module "+goLoaderBasicModule+"\n\ngo 1.26.1\n\nrequire example.com/extdep v1.0.0\n")
	writeTestFile(t, filepath.Join(root, "go.sum"), sums)
	writeTestFile(t, filepath.Join(root, "use", "use.go"), strings.Replace(
		mustReadTestFile(t, filepath.Join(root, "use", "use.go")),
		"\"example.com/basic/shape\"\n)",
		"\"example.com/basic/shape\"\n\t\"example.com/extdep/text\"\n)\n\nfunc Loud() string { return text.Upper(Describe()) }",
		1,
	))
	return root, cacheRoot
}

func TestGoLoaderDependencySnapshotIsSharedByEveryChunkOfAModule(t *testing.T) {
	root, cacheRoot := goLoaderExternalFixture(t)
	modules := goLoaderTestModules(t, root)

	whole := loadGoPackagesInventory(root, modules, WorkFile{}, nil)
	if whole.Status != "loaded" {
		t.Fatalf("module-whole-program status = %q: %+v", whole.Status, whole.Diagnostics)
	}
	if whole.DependencySnapshot.Status != "complete" || whole.DependencySnapshot.PackageCount != 1 {
		t.Fatalf("whole-program snapshot = %+v", whole.DependencySnapshot)
	}

	chunks := map[string]goPackagesInventory{}
	for _, dir := range []string{"use", "shape", "cmd/app"} {
		inventory := loadGoPackagesInventoryPackageScope(root, modules, []goLoaderTargetSpec{{Dir: dir}}, nil, WorkFile{}, nil, "", nil)
		if inventory.Status != "loaded" {
			t.Fatalf("chunk %s status = %q: %s", dir, inventory.Status, goLoaderDiagnosticSummary(inventory.Diagnostics))
		}
		chunks[dir] = inventory
	}
	for dir, inventory := range chunks {
		snapshot := inventory.DependencySnapshot
		if snapshot.Status != whole.DependencySnapshot.Status || snapshot.Fingerprint != whole.DependencySnapshot.Fingerprint {
			t.Fatalf("chunk %s snapshot %+v differs from the module-whole-program snapshot %+v", dir, snapshot, whole.DependencySnapshot)
		}
		if snapshot.PackageCount != 1 || snapshot.FileCount != 1 || snapshot.ModuleCount != 1 {
			t.Fatalf("chunk %s snapshot counts = %+v", dir, snapshot)
		}
	}
	// The chunk that imports the external module records it as an external
	// reference from the module cache; the others never mention it, yet all
	// three share the module-wide snapshot and therefore the base profile ID.
	useReport := chunks["use"].Loader
	if useReport.Metrics.ReferencesExternal != 1 {
		t.Fatalf("use chunk external references = %+v", useReport.Metrics)
	}
	if chunks["shape"].Loader.Metrics.ReferencesExternal != 0 {
		t.Fatalf("shape chunk external references = %+v", chunks["shape"].Loader.Metrics)
	}
	for _, reference := range useReport.References {
		if reference.Origin == goLoaderOriginExternal && (reference.PkgPath != "example.com/extdep/text" || reference.ModulePath != "example.com/extdep") {
			t.Fatalf("external reference = %+v", reference)
		}
	}
	profile := func(inventory goPackagesInventory) string {
		return goProfileID("linux", "amd64", "0", nil, "rta-cha", inventory.DependencySnapshot.Status, inventory.DependencySnapshot.Fingerprint)
	}
	if profile(chunks["use"]) != profile(chunks["shape"]) || profile(chunks["use"]) != profile(whole) {
		t.Fatal("chunks of one module derive different base profile identities")
	}
	// The per-chunk reference fingerprint is the part that legitimately
	// differs: use depends on shape in-repo, shape depends on nothing in-repo,
	// and external modules never enter it (the snapshot already covers them).
	if chunks["use"].Loader.ReferenceFingerprint.PackageCount != 1 || chunks["shape"].Loader.ReferenceFingerprint.PackageCount != 0 {
		t.Fatalf("reference fingerprints = %+v / %+v", chunks["use"].Loader.ReferenceFingerprint, chunks["shape"].Loader.ReferenceFingerprint)
	}
	if chunks["use"].Loader.ReferenceFingerprint.Fingerprint == chunks["shape"].Loader.ReferenceFingerprint.Fingerprint {
		t.Fatal("reference fingerprints must distinguish chunks with different in-repo closures")
	}
	// Changing the external module's source changes every chunk's snapshot
	// identically, exactly like the whole-program path.
	goLoaderMakeWritable(t, filepath.Join(cacheRoot, "example.com", "extdep@v1.0.0"))
	writeTestFile(t, filepath.Join(cacheRoot, "example.com", "extdep@v1.0.0", "text", "text.go"), "package text\n\nimport \"strings\"\n\nfunc Upper(value string) string { return strings.ToUpper(value) + \"!\" }\n")
	changedUse := loadGoPackagesInventoryPackageScope(root, modules, []goLoaderTargetSpec{{Dir: "use"}}, nil, WorkFile{}, nil, "", nil)
	changedShape := loadGoPackagesInventoryPackageScope(root, modules, []goLoaderTargetSpec{{Dir: "shape"}}, nil, WorkFile{}, nil, "", nil)
	if changedUse.DependencySnapshot.Fingerprint == whole.DependencySnapshot.Fingerprint || changedUse.DependencySnapshot.Fingerprint != changedShape.DependencySnapshot.Fingerprint {
		t.Fatalf("external source change was not observed uniformly: before=%s use=%s shape=%s", whole.DependencySnapshot.Fingerprint, changedUse.DependencySnapshot.Fingerprint, changedShape.DependencySnapshot.Fingerprint)
	}
}

func TestIsUnusedImportMessageMatchesGoTypesForms(t *testing.T) {
	cases := []struct {
		message string
		want    bool
	}{
		{`"fmt" imported and not used`, true},
		{`"fmt" imported as f and not used`, true},
		{`undefined: Foo`, false},
		{`imported and not used`, false},
	}
	for _, test := range cases {
		if got := isUnusedImportMessage(test.message); got != test.want {
			t.Fatalf("isUnusedImportMessage(%q) = %v, want %v", test.message, got, test.want)
		}
	}
}
