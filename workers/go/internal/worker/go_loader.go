package worker

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/tools/go/packages"
)

// goLoaderMode names how a typed/semantic unit obtains its type universe.
//
//   - module-whole-program is the historical path: one packages.Load per
//     module with NeedDeps|NeedSyntax, so every transitive dependency is parsed
//     and type-checked from source and RTA may run over the whole program.
//   - package is the hybrid loader in this file: only the target packages are
//     parsed and type-checked with bodies; dependencies are satisfied from
//     export data produced by `go list -export` over the dependency patterns
//     alone, so the toolchain never compiles the target itself.
type goLoaderMode string

const (
	goLoaderModeModuleWholeProgram goLoaderMode = "module-whole-program"
	goLoaderModePackage            goLoaderMode = "package"
)

// goSSAProgramScope is the completeness declaration attached to one SSA input.
// It is declared by the loader, never inferred from the loaded package graph.
type goSSAProgramScope string

const (
	// goSSAProgramScopeWholeProgram means every dependency carries syntax and
	// function bodies; RTA/VTA are permitted when the graph is complete.
	goSSAProgramScopeWholeProgram goSSAProgramScope = "whole-program"
	// goSSAProgramScopePackage means only the target packages carry bodies and
	// dependencies contribute declarations only. CHA is the only call-graph
	// algorithm that is sound over such a program.
	goSSAProgramScopePackage goSSAProgramScope = "package-with-declaration-deps"
)

const (
	// goLoaderMetadataMode lists a module without compiling or type-checking
	// anything. NeedTypes is deliberately absent so go/packages passes
	// -export=false to go list; NeedDeps keeps the transitive metadata graph
	// that the dependency snapshot and the reference fingerprint consume.
	goLoaderMetadataMode = packages.NeedName |
		packages.NeedFiles |
		packages.NeedCompiledGoFiles |
		packages.NeedImports |
		packages.NeedDeps |
		packages.NeedModule |
		packages.NeedForTest |
		packages.NeedEmbedFiles
	// goLoaderExportMode loads the listed dependency patterns from export data.
	// NeedTypes without NeedDeps makes go/packages request -export=true and read
	// gcexportdata for the roots instead of parsing them; their transitive
	// imports share the same type universe through the export-data view.
	goLoaderExportMode = packages.NeedName |
		packages.NeedFiles |
		packages.NeedCompiledGoFiles |
		packages.NeedImports |
		packages.NeedTypes |
		packages.NeedTypesSizes |
		packages.NeedModule

	goLoaderReferenceExport = "export"
	goLoaderReferenceSource = "source"

	goLoaderOriginInRepo   = "in-repo"
	goLoaderOriginExternal = "external"
	goLoaderOriginStandard = "standard-library"
)

// goLoaderTargetSpec selects one package directory of the scope module. Every
// build variant found in that directory (normal, internal test, external test)
// becomes a target; the synthetic test main is skipped.
type goLoaderTargetSpec struct {
	Dir     string // repository-relative package directory
	PkgPath string // optional import path used to validate the listing
}

// goLoaderScope is the loader-side scope of one unit: what may be loaded from
// source (targets) and where they live. Everything else the targets import is
// reference-only and is never widened by the loader.
type goLoaderScope struct {
	Module  Module
	Modules []Module
	Targets []goLoaderTargetSpec
	Tags    []string
	// Work is the GOWORK value handed to the Go command. Empty disables
	// workspace mode, matching the module-whole-program loader's default.
	Work string
	// Listing optionally supplies a module-wide metadata listing computed by a
	// previous step in the same session so it is not recomputed.
	Listing []*packages.Package
	// BodyPaths, when non-nil, stages the bodies of the target packages: only
	// the listed repository-relative files keep their function bodies for the
	// type-check and the SSA build, every other target file contributes its
	// declarations only. Generic functions, methods of generic types, and init
	// functions keep their bodies because go/types requires them.
	BodyPaths map[string]bool
}

type goLoaderReference struct {
	ID                string
	PkgPath           string
	Name              string
	ModulePath        string
	ModuleRelativeDir string
	Origin            string
	Source            string
	Direct            bool
}

// goReferencePackage is an in-repo dependency whose declarations were loaded
// without syntax. The semantic extractor synthesises the same canonical node
// identities the owning unit emits, so cross-unit calls and type uses join by
// string identity without ever sharing go/types objects across loads.
type goReferencePackage struct {
	ModulePath        string
	ModuleRelativeDir string
	ID                string
	PkgPath           string
	Name              string
	Types             *types.Package
	Source            string
}

type goLoaderMetrics struct {
	Mode           goLoaderMode
	TargetPackages int
	TargetFiles    int
	TargetBytes    int64
	// BodyFiles counts the target files whose function bodies were
	// type-checked; it equals TargetFiles unless the bodies were staged.
	BodyFiles           int
	StrippedFiles       int
	LoadedPackages      int
	SyntaxPackages      int
	ParsedFiles         int
	ReferencesExport    int
	ReferencesSource    int
	ReferencesInRepo    int
	ReferencesExternal  int
	ReferencesStandard  int
	ChildProcesses      int
	ListingMilliseconds int64
	ExportMilliseconds  int64
	CheckMilliseconds   int64
	ChildMaxRSSBytes    int64
	SelfPeakRSSBytes    int64
	BuildCacheShared    bool
	BuildCacheReused    bool
	Witness             string
}

type goLoaderResult struct {
	Status               string
	Mode                 goLoaderMode
	Targets              []*packages.Package
	TypedPackages        []goTypedPackage
	ReferencePackages    []goReferencePackage
	References           []goLoaderReference
	SSAInput             *goSSAInput
	Listing              []*packages.Package
	ReferenceFingerprint goReferenceFingerprint
	Metrics              goLoaderMetrics
	Diagnostics          []Diagnostic
}

type goBuildCacheState struct {
	Dir    string
	Shared bool
	Reused bool
}

// goLoaderSession owns the constrained Go command environment for one worker
// invocation. Every go list child process launched through it inherits the
// offline/readonly/no-driver environment of the module-whole-program loader;
// only GOCACHE may point at a caller-supplied scan-scoped build cache.
type goLoaderSession struct {
	root        string
	environment goCommandEnvironment
	buildCache  goBuildCacheState
	loader      goPackagesLoadFunc
	timeout     time.Duration
	digests     map[string]string
	closed      bool
}

func openGoLoaderSession(root, buildCacheDir string, loader goPackagesLoadFunc, timeout time.Duration) (*goLoaderSession, error) {
	if loader == nil {
		loader = packages.Load
	}
	if timeout <= 0 {
		timeout = goPackagesLoadTimeout
	}
	pathValue, err := safeGoCommandPath(root)
	if err != nil {
		return nil, err
	}
	environment, err := constrainedGoEnvironment(root, pathValue)
	if err != nil {
		return nil, err
	}
	session := &goLoaderSession{
		root: root, environment: environment, loader: loader, timeout: timeout, digests: map[string]string{},
		buildCache: goBuildCacheState{Dir: lookupEnvironmentValue(environment.Values, "GOCACHE")},
	}
	if buildCacheDir != "" {
		state, err := prepareGoBuildCache(root, buildCacheDir)
		if err != nil {
			environment.cleanup()
			return nil, err
		}
		session.environment.Values = replaceEnvironmentValue(session.environment.Values, "GOCACHE", state.Dir)
		session.buildCache = state
	}
	return session, nil
}

func (s *goLoaderSession) close() {
	if s == nil || s.closed {
		return
	}
	s.closed = true
	s.environment.cleanup()
}

// prepareGoBuildCache admits a scan-scoped shared build cache. The directory
// must be absolute, outside the scan root after symlink resolution, and free of
// path-list separators so it can never be smuggled into another variable.
func prepareGoBuildCache(root, dir string) (goBuildCacheState, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return goBuildCacheState{}, errors.New("the Go build cache directory must be an absolute path")
	}
	canonical := canonicalPathForConfinement(dir)
	if canonical == "" || !filepath.IsAbs(canonical) || isWithinRoot(root, canonical) || strings.ContainsRune(canonical, os.PathListSeparator) {
		return goBuildCacheState{}, errors.New("the Go build cache directory must be outside the scan root")
	}
	if err := os.MkdirAll(canonical, 0o700); err != nil {
		return goBuildCacheState{}, fmt.Errorf("create Go build cache: %w", err)
	}
	info, err := os.Lstat(canonical)
	if err != nil || !info.IsDir() {
		return goBuildCacheState{}, errors.New("the Go build cache directory is not a directory")
	}
	return goBuildCacheState{Dir: canonical, Shared: true, Reused: goBuildCachePopulated(canonical)}, nil
}

// goBuildCachePopulated reports whether a Go build cache already holds
// entries. The cache layout is <dir>/<2 hex digits>/<entry>; README and
// trim.txt alone do not count as reuse.
func goBuildCachePopulated(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || len(name) != 2 || strings.Trim(name, "0123456789abcdef") != "" {
			continue
		}
		bucket, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		names, _ := bucket.Readdirnames(1)
		_ = bucket.Close()
		if len(names) > 0 {
			return true
		}
	}
	return false
}

func lookupEnvironmentValue(values []string, key string) string {
	prefix := key + "="
	for index := len(values) - 1; index >= 0; index-- {
		if strings.HasPrefix(values[index], prefix) {
			return strings.TrimPrefix(values[index], prefix)
		}
	}
	return ""
}

func replaceEnvironmentValue(values []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(values)+1)
	for _, entry := range values {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+value)
}

func (s *goLoaderSession) commandEnvironment(work string) []string {
	if work == "" {
		work = "off"
	}
	environment := append([]string{}, s.environment.Values...)
	return append(environment, "GOWORK="+work)
}

func (s *goLoaderSession) load(dir, work string, mode packages.LoadMode, tests bool, tags []string, fset *token.FileSet, patterns ...string) ([]*packages.Package, error) {
	loadContext, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	config := &packages.Config{
		Context: loadContext, Dir: dir, Env: s.commandEnvironment(work), Mode: mode, Tests: tests, Fset: fset,
	}
	if len(tags) > 0 {
		config.BuildFlags = []string{"-tags=" + strings.Join(tags, ",")}
	}
	loaded, err := s.loader(config, patterns...)
	if contextErr := loadContext.Err(); errors.Is(contextErr, context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return nil, context.DeadlineExceeded
	}
	return loaded, err
}

// listModule is the module-wide metadata listing: every package and test
// variant of the module with build-constrained file lists, module metadata and
// the transitive import graph, but no compile and no type-check.
func (s *goLoaderSession) listModule(module Module, work string, tags []string) ([]*packages.Package, error) {
	loaded, err := s.load(module.Dir, work, goLoaderMetadataMode, true, tags, nil, "./...")
	if err != nil {
		return nil, err
	}
	sort.SliceStable(loaded, func(left, right int) bool {
		if loaded[left] == nil || loaded[right] == nil {
			return loaded[left] != nil
		}
		return loaded[left].ID < loaded[right].ID
	})
	return loaded, nil
}

// goLoaderRun carries the state of one package-scope load.
type goLoaderRun struct {
	session     *goLoaderSession
	scope       goLoaderScope
	fset        *token.FileSet
	sizes       types.Sizes
	byID        map[string]*packages.Package
	targets     map[string]*packages.Package
	exportRoots map[string]*packages.Package
	exportByID  map[string]*packages.Package
	checked     map[string]*packages.Package
	inProgress  map[string]bool
	references  map[string]*goLoaderReference
	unsafePkg   *packages.Package
	result      *goLoaderResult
	incomplete  bool
	errorCount  int
	seenErrors  map[string]bool
	truncated   bool
	progress    AnalysisProgressFunc
	checkedUnit int
}

// loadPackageScope runs the hybrid loader for one scope. The returned typed
// packages carry syntax and full types.Info only for the target variants; the
// SSA input is declared package-with-declaration-deps so the semantic stage
// never attempts RTA/VTA over export-data dependencies.
func (s *goLoaderSession) loadPackageScope(scope goLoaderScope, progress AnalysisProgressFunc) goLoaderResult {
	run := &goLoaderRun{
		session: s, scope: scope, fset: token.NewFileSet(),
		byID: map[string]*packages.Package{}, targets: map[string]*packages.Package{},
		exportRoots: map[string]*packages.Package{}, exportByID: map[string]*packages.Package{},
		checked: map[string]*packages.Package{}, inProgress: map[string]bool{},
		references: map[string]*goLoaderReference{}, seenErrors: map[string]bool{},
		result:   &goLoaderResult{Status: "fallback", Mode: goLoaderModePackage},
		progress: progress,
	}
	run.result.Metrics.Mode = goLoaderModePackage
	run.result.Metrics.BuildCacheShared = s.buildCache.Shared
	run.result.Metrics.BuildCacheReused = s.buildCache.Reused
	run.execute()
	run.result.Metrics.ChildMaxRSSBytes = goChildMaxRSSBytes()
	run.result.Metrics.SelfPeakRSSBytes = goSelfPeakRSSBytes()
	return *run.result
}

func (r *goLoaderRun) fail(code, message string) {
	r.incomplete = true
	r.addDiagnostic(code, "warning", message)
}

func (r *goLoaderRun) addDiagnostic(code, severity, message string) {
	module := r.scope.Module
	path := relativePath(r.session.root, module.ManifestPath)
	if module.ManifestPath == "" {
		path = ""
	}
	message = normalizeGoPackagesMessage(r.session.root, message, r.session.environment.NeutralRoot, r.session.buildCache.Dir)
	key := code + "\x00" + message
	if r.seenErrors[key] {
		return
	}
	r.seenErrors[key] = true
	if severity == "warning" {
		if r.errorCount >= maxGoPackagesErrors {
			r.truncated = true
			return
		}
		r.errorCount++
	}
	r.result.Diagnostics = append(r.result.Diagnostics, Diagnostic{
		Code: code, Severity: severity, Message: message, Path: path, Recoverable: true,
	})
}

func (r *goLoaderRun) execute() {
	module := r.scope.Module
	root := r.session.root
	if module.ManifestPath == "" {
		r.fail("go_loader_scope_invalid", "the loader scope module has no go.mod")
		return
	}
	if len(r.scope.Targets) == 0 {
		r.fail("go_loader_scope_invalid", "the loader scope selects no target packages")
		return
	}
	r.sizes = types.SizesFor("gc", runtime.GOARCH)
	if r.sizes == nil {
		r.fail("go_loader_scope_invalid", "no gc type sizes are available for "+runtime.GOARCH)
		return
	}
	moduleDir := canonicalPathForConfinement(module.Dir)
	targetDirs := map[string]goLoaderTargetSpec{}
	for _, target := range r.scope.Targets {
		if target.Dir == "" || filepath.IsAbs(filepath.FromSlash(target.Dir)) {
			r.fail("go_loader_scope_invalid", fmt.Sprintf("target directory %q is not repository-relative", target.Dir))
			return
		}
		candidate := canonicalPathForConfinement(filepath.Join(root, filepath.FromSlash(target.Dir)))
		if candidate == "" || !isWithinRoot(root, candidate) || !isWithinRoot(moduleDir, candidate) {
			r.fail("go_loader_scope_invalid", fmt.Sprintf("target directory %q is outside the scope module", target.Dir))
			return
		}
		if _, duplicate := targetDirs[candidate]; duplicate {
			r.fail("go_loader_scope_invalid", fmt.Sprintf("target directory %q is selected twice", target.Dir))
			return
		}
		targetDirs[candidate] = target
	}

	// Step 1: module-wide metadata listing.
	listing := r.scope.Listing
	if listing == nil {
		started := time.Now()
		loaded, err := r.session.listModule(module, r.scope.Work, r.scope.Tags)
		r.result.Metrics.ListingMilliseconds = time.Since(started).Milliseconds()
		r.result.Metrics.ChildProcesses++
		if errors.Is(err, context.DeadlineExceeded) {
			r.fail("go_loader_listing_timeout", "module metadata listing timed out under offline/read-only constraints")
			return
		}
		if err != nil {
			r.fail("go_loader_listing_failed", "module metadata listing failed under offline/read-only constraints: "+err.Error())
			return
		}
		listing = loaded
	}
	r.result.Listing = listing
	packages.Visit(listing, nil, func(pkg *packages.Package) {
		if pkg != nil && pkg.ID != "" {
			r.byID[pkg.ID] = pkg
		}
	})

	// Select the target variants by package directory.
	matched := map[string]bool{}
	var targetOrder []*packages.Package
	for _, pkg := range listing {
		if pkg == nil || goLoaderIsTestMain(pkg) {
			continue
		}
		dir := canonicalPathForConfinement(pkg.Dir)
		if dir == "" {
			dir = goLoaderPackageDir(root, pkg)
		}
		spec, ok := targetDirs[dir]
		if !ok {
			continue
		}
		if spec.PkgPath != "" && pkg.PkgPath != spec.PkgPath && pkg.PkgPath != spec.PkgPath+"_test" {
			r.fail("go_loader_target_mismatch", fmt.Sprintf("target directory %q lists package %q instead of %q", spec.Dir, pkg.PkgPath, spec.PkgPath))
			continue
		}
		if !packageBelongsToModule(root, module, pkg) {
			r.fail("go_loader_target_mismatch", fmt.Sprintf("package %q does not belong to the scope module", pkg.ID))
			continue
		}
		matched[dir] = true
		r.targets[pkg.ID] = pkg
		targetOrder = append(targetOrder, pkg)
	}
	for dir, spec := range targetDirs {
		if !matched[dir] {
			r.fail("go_loader_target_missing", fmt.Sprintf("target directory %q has no build-constrained Go package in the module listing", spec.Dir))
		}
	}
	if len(targetOrder) == 0 {
		return
	}
	sort.SliceStable(targetOrder, func(left, right int) bool {
		leftRank, rightRank := goLoaderVariantRank(targetOrder[left]), goLoaderVariantRank(targetOrder[right])
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return targetOrder[left].ID < targetOrder[right].ID
	})
	for _, target := range targetOrder {
		for _, packageErr := range target.Errors {
			r.fail("go_loader_target_incomplete", "go list reported incomplete offline metadata for "+target.ID+": "+normalizeGoPackagesError(root, packageErr))
		}
	}

	// Step 2: dependency export load for the direct imports of every target
	// variant. Test-recompiled dependency variants cannot come from export
	// data; they are loaded from source without bodies in step 3.
	exportPaths := map[string]bool{}
	for _, target := range targetOrder {
		r.collectExportPatterns(target, exportPaths, map[string]bool{})
	}
	if r.incomplete {
		return
	}
	patterns := make([]string, 0, len(exportPaths))
	for path := range exportPaths {
		patterns = append(patterns, path)
	}
	sort.Strings(patterns)
	if len(patterns) > 0 {
		started := time.Now()
		loaded, err := r.session.load(module.Dir, r.scope.Work, goLoaderExportMode, false, r.scope.Tags, r.fset, patterns...)
		r.result.Metrics.ExportMilliseconds = time.Since(started).Milliseconds()
		r.result.Metrics.ChildProcesses++
		if errors.Is(err, context.DeadlineExceeded) {
			r.fail("go_loader_export_timeout", "dependency export-data load timed out under offline/read-only constraints")
			return
		}
		if err != nil {
			r.fail("go_loader_export_failed", "dependency export-data load failed under offline/read-only constraints: "+err.Error())
			return
		}
		for _, pkg := range loaded {
			if pkg == nil {
				continue
			}
			r.exportRoots[pkg.PkgPath] = pkg
		}
		packages.Visit(loaded, nil, func(pkg *packages.Package) {
			if pkg != nil {
				r.exportByID[pkg.ID] = pkg
			}
		})
		missing := make([]string, 0)
		for _, pattern := range patterns {
			if r.exportRoots[pattern] == nil {
				missing = append(missing, pattern)
			}
		}
		for _, pattern := range missing {
			r.fail("go_loader_export_incomplete", fmt.Sprintf("dependency %q was not returned by the export-data load", pattern))
		}
		for _, pattern := range patterns {
			pkg := r.exportRoots[pattern]
			if pkg == nil {
				continue
			}
			for _, packageErr := range pkg.Errors {
				r.fail("go_loader_export_incomplete", "dependency "+pkg.ID+" has incomplete export data: "+normalizeGoPackagesError(root, packageErr))
			}
			if pkg.Types == nil || pkg.IllTyped {
				r.fail("go_loader_export_incomplete", "dependency "+pkg.ID+" has no complete export data")
			}
			if len(pkg.Syntax) > 0 {
				r.fail("go_loader_export_incomplete", "dependency "+pkg.ID+" fell back to source type-checking")
			}
		}
	}
	if r.incomplete {
		return
	}

	// Step 3: in-process type-check of the target variants in identity order.
	started := time.Now()
	for _, target := range targetOrder {
		out, err := r.checkVariant(target, false)
		if err != nil {
			r.fail("go_loader_target_incomplete", "package "+target.ID+" could not be type-checked: "+err.Error())
			continue
		}
		r.checkedUnit++
		if r.progress != nil {
			r.progress("go_typed_load", "progress", r.checkedUnit)
		}
		r.result.Targets = append(r.result.Targets, out)
	}
	r.result.Metrics.CheckMilliseconds = time.Since(started).Milliseconds()
	for _, target := range r.result.Targets {
		for _, packageErr := range target.Errors {
			r.fail("go_loader_target_incomplete", "package "+target.ID+" is ill-typed: "+normalizeGoPackagesError(root, packageErr))
		}
	}
	if r.truncated {
		r.addDiagnostic("go_packages_errors_truncated", "warning", fmt.Sprintf("go/packages diagnostics were limited to %d entries", maxGoPackagesErrors))
	}
	r.finish()
}

// collectExportPatterns records the import paths that must come from export
// data for one target or source-reference variant. Imports of other targets
// and the "unsafe" pseudo-package are satisfied in-process.
func (r *goLoaderRun) collectExportPatterns(pkg *packages.Package, exportPaths map[string]bool, visited map[string]bool) {
	if pkg == nil || visited[pkg.ID] {
		return
	}
	visited[pkg.ID] = true
	importPaths := make([]string, 0, len(pkg.Imports))
	for importPath := range pkg.Imports {
		importPaths = append(importPaths, importPath)
	}
	sort.Strings(importPaths)
	for _, importPath := range importPaths {
		imported := pkg.Imports[importPath]
		if imported == nil {
			r.fail("go_loader_target_incomplete", fmt.Sprintf("package %q has no metadata for import %q", pkg.ID, importPath))
			continue
		}
		if importPath == "unsafe" || r.targets[imported.ID] != nil {
			continue
		}
		if importPath == "C" {
			r.fail("go_loader_target_incomplete", fmt.Sprintf("package %q imports \"C\" but cgo is disabled in safe mode", pkg.ID))
			continue
		}
		if imported.ID != imported.PkgPath {
			// Test-recompiled variant such as "q [p.test]": follow its imports so
			// the export load still covers everything it needs.
			r.collectExportPatterns(imported, exportPaths, visited)
			continue
		}
		exportPaths[imported.PkgPath] = true
	}
}

func goLoaderVariantRank(pkg *packages.Package) int {
	switch {
	case pkg.ForTest == "":
		return 0
	case pkg.PkgPath == pkg.ForTest:
		return 1
	default:
		return 2
	}
}

func goLoaderIsTestMain(pkg *packages.Package) bool {
	return pkg != nil && pkg.Name == "main" && strings.HasSuffix(pkg.ID, ".test") && strings.HasSuffix(pkg.PkgPath, ".test")
}

func goLoaderPackageDir(root string, pkg *packages.Package) string {
	for _, file := range append(append([]string(nil), pkg.CompiledGoFiles...), pkg.GoFiles...) {
		if confined, ok := confinedMetadataFile(root, file); ok {
			return filepath.Dir(confined)
		}
	}
	return ""
}

// checkVariant parses and type-checks one listed package variant in the shared
// FileSet. ignoreBodies is used for test-recompiled dependency variants that
// only contribute declarations.
func (r *goLoaderRun) checkVariant(variant *packages.Package, ignoreBodies bool) (*packages.Package, error) {
	if existing := r.checked[variant.ID]; existing != nil {
		return existing, nil
	}
	if r.inProgress[variant.ID] {
		return nil, fmt.Errorf("import cycle through %q", variant.ID)
	}
	r.inProgress[variant.ID] = true
	defer delete(r.inProgress, variant.ID)

	root := r.session.root
	files := make([]*ast.File, 0, len(variant.CompiledGoFiles))
	var packageErrors []packages.Error
	var bytesRead int64
	stripped := map[string]bool{}
	bodyFiles := 0
	for _, file := range variant.CompiledGoFiles {
		confined, ok := confinedMetadataFile(root, file)
		if !ok {
			if candidate := r.admittedExternalFile(file); candidate != "" {
				confined = candidate
			} else {
				return nil, fmt.Errorf("compiled file %q is not confined to an admitted source root", file)
			}
		}
		source, err := os.ReadFile(confined)
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", relativePath(root, confined), err)
		}
		bytesRead += int64(len(source))
		syntax, err := parser.ParseFile(r.fset, confined, source, parser.AllErrors|parser.ParseComments)
		if syntax == nil {
			return nil, fmt.Errorf("parse %q: %v", relativePath(root, confined), err)
		}
		if err != nil {
			var list scanner.ErrorList
			if errors.As(err, &list) {
				for _, item := range list {
					packageErrors = append(packageErrors, packages.Error{Pos: item.Pos.String(), Msg: item.Msg, Kind: packages.ParseError})
				}
			} else {
				packageErrors = append(packageErrors, packages.Error{Pos: "-", Msg: err.Error(), Kind: packages.ParseError})
			}
		}
		if !ignoreBodies && r.scope.BodyPaths != nil && !r.scope.BodyPaths[cleanSlash(relativePath(root, confined))] {
			stripFunctionBodies(syntax)
			stripped[confined] = true
		} else if !ignoreBodies {
			bodyFiles++
		}
		files = append(files, syntax)
	}
	r.result.Metrics.ParsedFiles += len(files)
	if !ignoreBodies {
		r.result.Metrics.TargetPackages++
		r.result.Metrics.TargetFiles += len(files)
		r.result.Metrics.TargetBytes += bytesRead
		r.result.Metrics.BodyFiles += bodyFiles
		r.result.Metrics.StrippedFiles += len(stripped)
	}

	imports := map[string]*packages.Package{}
	importer := &goLoaderImporter{run: r, variant: variant, imports: imports}
	config := &types.Config{
		Importer:         importer,
		IgnoreFuncBodies: ignoreBodies,
		Sizes:            r.sizes,
		Error: func(err error) {
			if typeErr, ok := err.(types.Error); ok {
				position := typeErr.Fset.Position(typeErr.Pos)
				if stripped[position.Filename] && isUnusedImportMessage(typeErr.Msg) {
					// The import was used by a body this chunk does not own;
					// the owning chunk type-checks it with the body present.
					return
				}
				packageErrors = append(packageErrors, packages.Error{Pos: position.String(), Msg: typeErr.Msg, Kind: packages.TypeError})
				return
			}
			packageErrors = append(packageErrors, packages.Error{Pos: "-", Msg: err.Error(), Kind: packages.TypeError})
		},
	}
	if variant.Module != nil && variant.Module.GoVersion != "" {
		config.GoVersion = "go" + variant.Module.GoVersion
	}
	var info *types.Info
	if !ignoreBodies {
		info = &types.Info{
			Types:        map[ast.Expr]types.TypeAndValue{},
			Defs:         map[*ast.Ident]types.Object{},
			Uses:         map[*ast.Ident]types.Object{},
			Implicits:    map[ast.Node]types.Object{},
			Instances:    map[*ast.Ident]types.Instance{},
			Scopes:       map[ast.Node]*types.Scope{},
			Selections:   map[*ast.SelectorExpr]*types.Selection{},
			FileVersions: map[*ast.File]string{},
		}
	}
	typesPackage := types.NewPackage(variant.PkgPath, variant.Name)
	checker := types.NewChecker(config, r.fset, typesPackage, info)
	_ = checker.Files(files)
	if importer.err != nil {
		return nil, importer.err
	}
	sort.SliceStable(packageErrors, func(left, right int) bool {
		if packageErrors[left].Pos != packageErrors[right].Pos {
			return packageErrors[left].Pos < packageErrors[right].Pos
		}
		return packageErrors[left].Msg < packageErrors[right].Msg
	})
	out := &packages.Package{
		ID: variant.ID, Name: variant.Name, PkgPath: variant.PkgPath, ForTest: variant.ForTest,
		Dir: variant.Dir, Module: variant.Module,
		GoFiles: append([]string(nil), variant.GoFiles...), CompiledGoFiles: append([]string(nil), variant.CompiledGoFiles...),
		OtherFiles: append([]string(nil), variant.OtherFiles...), EmbedFiles: append([]string(nil), variant.EmbedFiles...),
		Imports: imports, Fset: r.fset, Types: typesPackage, TypesSizes: r.sizes,
		IllTyped: len(packageErrors) > 0, Errors: packageErrors,
	}
	if !ignoreBodies {
		out.Syntax = files
		out.TypesInfo = info
	}
	r.checked[variant.ID] = out
	return out, nil
}

// stripFunctionBodies turns the function declarations of one target file into
// body-less declarations so go/types checks the signatures only and go/ssa
// treats the functions as external. Bodies that go/types insists on stay:
// generic functions ("generic function is missing function body"), init
// functions ("func init must have a body"), and methods of generic types whose
// instantiation the SSA builder must be able to synthesise.
func stripFunctionBodies(file *ast.File) {
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		if function.Type.TypeParams != nil && len(function.Type.TypeParams.List) > 0 {
			continue
		}
		if function.Recv == nil && function.Name != nil && function.Name.Name == "init" {
			continue
		}
		if function.Recv != nil && receiverIsGeneric(function.Recv) {
			continue
		}
		function.Body = nil
	}
}

func receiverIsGeneric(receiver *ast.FieldList) bool {
	generic := false
	for _, field := range receiver.List {
		ast.Inspect(field.Type, func(node ast.Node) bool {
			switch node.(type) {
			case *ast.IndexExpr, *ast.IndexListExpr:
				generic = true
			}
			return !generic
		})
	}
	return generic
}

func isUnusedImportMessage(message string) bool {
	return strings.HasPrefix(message, "\"") && strings.HasSuffix(message, "and not used") && strings.Contains(message, "imported")
}

// admittedExternalFile admits a dependency source file that lives outside the
// scan root only when it is a regular file inside the constrained module cache.
func (r *goLoaderRun) admittedExternalFile(file string) string {
	cache := canonicalPathForConfinement(r.session.environment.ModuleCache)
	if cache == "" || !filepath.IsAbs(file) {
		return ""
	}
	candidate := canonicalPathForConfinement(file)
	if candidate == "" || !isWithinRoot(cache, candidate) {
		return ""
	}
	info, err := os.Lstat(candidate)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return candidate
}

type goLoaderImporter struct {
	run     *goLoaderRun
	variant *packages.Package
	imports map[string]*packages.Package
	err     error
}

func (i *goLoaderImporter) Import(path string) (*types.Package, error) {
	pkg, err := i.run.resolveImport(i.variant, path)
	if err != nil {
		if i.err == nil {
			i.err = err
		}
		return nil, err
	}
	i.imports[path] = pkg
	return pkg.Types, nil
}

func (r *goLoaderRun) unsafePackage() *packages.Package {
	if r.unsafePkg == nil {
		if fromExport := r.exportByID["unsafe"]; fromExport != nil && fromExport.Types != nil {
			r.unsafePkg = fromExport
		} else {
			r.unsafePkg = &packages.Package{ID: "unsafe", Name: "unsafe", PkgPath: "unsafe", Types: types.Unsafe, Fset: r.fset, TypesSizes: r.sizes}
		}
	}
	return r.unsafePkg
}

// resolveImport maps one import of a listed variant onto exactly one package
// of this load: a checked target variant, a source-loaded test-recompiled
// variant, or an export-data root. It never creates a second type universe for
// the same identity.
func (r *goLoaderRun) resolveImport(variant *packages.Package, path string) (*packages.Package, error) {
	if path == "unsafe" {
		return r.unsafePackage(), nil
	}
	if path == "C" {
		return nil, errors.New(`import "C" is unavailable because cgo is disabled in safe mode`)
	}
	stub := variant.Imports[path]
	if stub == nil {
		return nil, fmt.Errorf("import %q is not declared in the package metadata of %q", path, variant.ID)
	}
	if checked := r.checked[stub.ID]; checked != nil {
		return checked, nil
	}
	if r.targets[stub.ID] != nil {
		return r.checkVariant(r.targets[stub.ID], false)
	}
	if stub.ID != stub.PkgPath {
		full := r.byID[stub.ID]
		if full == nil {
			full = stub
		}
		out, err := r.checkVariant(full, true)
		if err != nil {
			return nil, fmt.Errorf("test-recompiled dependency %q: %w", stub.ID, err)
		}
		r.recordReference(full, goLoaderReferenceSource, true)
		return out, nil
	}
	export := r.exportRoots[stub.PkgPath]
	if export == nil || export.Types == nil {
		return nil, fmt.Errorf("no export data for %q", path)
	}
	r.recordReference(export, goLoaderReferenceExport, true)
	return export, nil
}

func (r *goLoaderRun) recordReference(pkg *packages.Package, source string, direct bool) {
	if pkg == nil {
		return
	}
	if existing := r.references[pkg.ID]; existing != nil {
		existing.Direct = existing.Direct || direct
		return
	}
	origin, module := goLoaderClassifyPackage(r.session.root, r.scope.Modules, pkg)
	reference := &goLoaderReference{
		ID: pkg.ID, PkgPath: pkg.PkgPath, Name: pkg.Name, Origin: origin, Source: source, Direct: direct,
	}
	if origin == goLoaderOriginInRepo {
		reference.ModulePath = module.Path
		reference.ModuleRelativeDir = module.RelativeDir
	} else if pkg.Module != nil {
		reference.ModulePath = pkg.Module.Path
	}
	r.references[pkg.ID] = reference
}

// goLoaderClassifyPackage decides whether a loaded package is owned by a
// discovered in-repo module, by the standard library, or by an external
// module. In-repo packages are identified by their effective module directory
// (after local replacement) so same-path modules in different directories keep
// distinct identities.
func goLoaderClassifyPackage(root string, modules []Module, pkg *packages.Package) (string, Module) {
	if pkg == nil {
		return goLoaderOriginExternal, Module{}
	}
	if pkg.Module != nil {
		effective := pkg.Module
		if effective.Replace != nil {
			effective = effective.Replace
		}
		dir := canonicalPathForConfinement(effective.Dir)
		if dir != "" && isWithinRoot(root, dir) {
			for _, module := range modules {
				if canonicalPathForConfinement(module.Dir) == dir {
					return goLoaderOriginInRepo, module
				}
			}
			return goLoaderOriginInRepo, Module{Dir: dir, RelativeDir: relativePath(root, dir), Path: effective.Path}
		}
		return goLoaderOriginExternal, Module{}
	}
	files := append(append([]string(nil), pkg.GoFiles...), pkg.CompiledGoFiles...)
	if looksLikeStandardLibrary(pkg.PkgPath) || dependencySnapshotAnyFileWithin(runtimeGoRoot(), files) {
		return goLoaderOriginStandard, Module{}
	}
	for _, file := range files {
		if confined, ok := confinedMetadataFile(root, file); ok {
			if module := moduleForPath(modules, confined); module != nil {
				return goLoaderOriginInRepo, *module
			}
		}
	}
	return goLoaderOriginExternal, Module{}
}

// finish assembles typed packages, references, metrics and the SSA input once
// every target variant has been checked. Any incompleteness fails closed: no
// typed package is retained so the parser inventory stays authoritative.
func (r *goLoaderRun) finish() {
	root := r.session.root
	module := r.scope.Module
	packages.Visit(r.result.Targets, nil, func(pkg *packages.Package) {
		if pkg == nil {
			return
		}
		r.result.Metrics.LoadedPackages++
		if len(pkg.Syntax) > 0 {
			r.result.Metrics.SyntaxPackages++
		}
		if r.targets[pkg.ID] == nil && pkg.PkgPath != "unsafe" {
			source := goLoaderReferenceExport
			if r.checked[pkg.ID] != nil {
				source = goLoaderReferenceSource
			}
			r.recordReference(pkg, source, false)
		}
	})
	referenceIDs := make([]string, 0, len(r.references))
	for id := range r.references {
		referenceIDs = append(referenceIDs, id)
	}
	sort.Strings(referenceIDs)
	for _, id := range referenceIDs {
		reference := *r.references[id]
		r.result.References = append(r.result.References, reference)
		switch reference.Source {
		case goLoaderReferenceExport:
			r.result.Metrics.ReferencesExport++
		case goLoaderReferenceSource:
			r.result.Metrics.ReferencesSource++
		}
		switch reference.Origin {
		case goLoaderOriginInRepo:
			r.result.Metrics.ReferencesInRepo++
		case goLoaderOriginExternal:
			r.result.Metrics.ReferencesExternal++
		case goLoaderOriginStandard:
			r.result.Metrics.ReferencesStandard++
		}
		if reference.Origin == goLoaderOriginInRepo {
			pkg := r.exportByID[id]
			if pkg == nil {
				pkg = r.checked[id]
			}
			if pkg != nil && pkg.Types != nil {
				r.result.ReferencePackages = append(r.result.ReferencePackages, goReferencePackage{
					ModulePath: reference.ModulePath, ModuleRelativeDir: reference.ModuleRelativeDir,
					ID: pkg.ID, PkgPath: pkg.PkgPath, Name: pkg.Name, Types: pkg.Types, Source: reference.Source,
				})
			}
		}
	}
	r.result.Metrics.Witness = goLoaderWitness(root, r.result.Targets)
	r.result.ReferenceFingerprint = computeGoReferenceFingerprint(root, r.scope.Modules, targetListing(r.result.Listing, r.targets), r.session.digests)
	if r.incomplete {
		return
	}
	typedPackages := make([]goTypedPackage, 0, len(r.result.Targets))
	for _, target := range r.result.Targets {
		typed, err := collectGoTypedPackage(root, module, target)
		if err != nil {
			r.fail("go_loader_target_incomplete", fmt.Sprintf("package %q has incomplete typed data: %v", target.ID, err))
			return
		}
		typedPackages = append(typedPackages, typed)
	}
	ssaInput := &goSSAInput{
		ModulePath: module.Path, ModuleRelativeDir: module.RelativeDir,
		Roots: append([]*packages.Package(nil), r.result.Targets...), ProgramScope: goSSAProgramScopePackage,
	}
	for index := range typedPackages {
		typedPackages[index].SSAInput = ssaInput
	}
	sort.SliceStable(typedPackages, func(left, right int) bool {
		if typedPackages[left].ID != typedPackages[right].ID {
			return typedPackages[left].ID < typedPackages[right].ID
		}
		return typedPackages[left].ForTest < typedPackages[right].ForTest
	})
	r.result.TypedPackages = typedPackages
	r.result.SSAInput = ssaInput
	r.result.Status = "loaded"
}

func targetListing(listing []*packages.Package, targets map[string]*packages.Package) []*packages.Package {
	result := make([]*packages.Package, 0, len(targets))
	for _, pkg := range listing {
		if pkg != nil && targets[pkg.ID] != nil {
			result = append(result, pkg)
		}
	}
	return result
}

// goLoaderWitness digests exactly which packages and files took part in the
// load. It is chunk-level evidence and never part of a profile identity.
func goLoaderWitness(root string, roots []*packages.Package) string {
	type witnessEntry struct {
		ID        string   `json:"id"`
		PkgPath   string   `json:"pkg_path"`
		Module    string   `json:"module"`
		Syntax    bool     `json:"syntax"`
		Files     []string `json:"files"`
		FileCount int      `json:"file_count"`
	}
	var entries []witnessEntry
	goRoot := runtimeGoRoot()
	packages.Visit(roots, nil, func(pkg *packages.Package) {
		if pkg == nil {
			return
		}
		entry := witnessEntry{ID: pkg.ID, PkgPath: pkg.PkgPath, Syntax: len(pkg.Syntax) > 0}
		base := ""
		if pkg.Module != nil {
			effective := pkg.Module
			if effective.Replace != nil {
				effective = effective.Replace
			}
			base = canonicalPathForConfinement(effective.Dir)
			entry.Module = effective.Path + "@" + effective.Version
			if base != "" && isWithinRoot(root, base) {
				entry.Module = "repo:" + relativePath(root, base)
			}
		}
		files := dependencySnapshotPackageFiles(pkg)
		entry.FileCount = len(files)
		for _, file := range files {
			candidate := canonicalPathForConfinement(file)
			switch {
			case candidate != "" && isWithinRoot(root, candidate):
				entry.Files = append(entry.Files, relativePath(root, candidate))
			case base != "" && candidate != "" && isWithinRoot(base, candidate):
				entry.Files = append(entry.Files, relativePath(base, candidate))
			case goRoot != "" && candidate != "" && isWithinRoot(goRoot, candidate):
				entry.Files = append(entry.Files, "$GOROOT/"+relativePath(goRoot, candidate))
			default:
				entry.Files = append(entry.Files, filepath.Base(file))
			}
		}
		sort.Strings(entry.Files)
		entries = append(entries, entry)
	})
	sort.SliceStable(entries, func(left, right int) bool {
		if entries[left].Module != entries[right].Module {
			return entries[left].Module < entries[right].Module
		}
		return entries[left].ID < entries[right].ID
	})
	return stableIDFromValue("go_loader_witness", entries)
}
