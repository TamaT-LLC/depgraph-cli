package worker

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"
)

const (
	goPackagesLoadTimeout = 30 * time.Second
	maxGoPackagesErrors   = 20
)

// goTypedPackage keeps the type universe and syntax returned by one confined
// go/packages load together. Packages and files are sorted before they reach
// scannerState; consumers must likewise sort any go/types map before emitting
// protocol data.
type goTypedPackage struct {
	ModulePath        string
	ModuleRelativeDir string
	ID                string
	PkgPath           string
	Name              string
	ForTest           string
	Files             []goTypedFile
	FileSet           *token.FileSet
	Types             *types.Package
	TypesInfo         *types.Info
	TypesSizes        types.Sizes
	SSAInput          *goSSAInput
}

// goSSAInput preserves exactly one successful packages.Load type universe.
// SSA programs must never combine packages from separate loads because their
// FileSet and go/types object identities are unrelated.
type goSSAInput struct {
	ModulePath        string
	ModuleRelativeDir string
	Roots             []*packages.Package
}

type goTypedFile struct {
	Path   string
	Syntax *ast.File
}

type goPackagesLoadFunc func(*packages.Config, ...string) ([]*packages.Package, error)

type goCommandEnvironment struct {
	Values            []string
	NeutralRoot       string
	TelemetryModePath string
	ModuleCache       string
	cleanup           func()
}

type goModulePreflight struct {
	Code   string
	Reason string
}

// goPackagesInventory augments the static parser inventory with typed package
// data. The standard-library parser remains authoritative for dependency sites,
// spans, and syntax coverage so an incomplete typed load cannot erase source.
type goPackagesInventory struct {
	Status             string
	ModuleCount        int
	PackageCount       int
	ActiveFileCount    int
	CompiledFileCount  int
	EmbedFileCount     int
	TestVariantCount   int
	TypedPackages      []goTypedPackage
	Fallback           bool
	Diagnostics        []Diagnostic
	DependencySnapshot goDependencySnapshot
}

func loadGoPackagesInventory(root string, modules []Module, work WorkFile, tags []string) goPackagesInventory {
	return loadGoPackagesInventoryWith(root, modules, work, tags, packages.Load, goPackagesLoadTimeout)
}

func loadGoPackagesInventoryWith(root string, modules []Module, work WorkFile, tags []string, loader goPackagesLoadFunc, timeout time.Duration) (inventory goPackagesInventory) {
	inventory = goPackagesInventory{Status: "fallback", Fallback: true}
	dependencySnapshot := newGoDependencySnapshotBuilder(root, modules, work)
	defer func() {
		inventory.DependencySnapshot = dependencySnapshot.finalize(inventory.Status)
	}()
	if len(modules) == 0 || (len(modules) == 1 && modules[0].ManifestPath == "") {
		inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(
			root,
			"go_packages_no_module",
			"info",
			"go/packages was not invoked because no confined go.mod was discovered; the static parser inventory was retained",
		))
		return inventory
	}
	orderedModules := append([]Module(nil), modules...)
	sort.SliceStable(orderedModules, func(left, right int) bool {
		if orderedModules[left].ManifestPath != orderedModules[right].ManifestPath {
			return orderedModules[left].ManifestPath < orderedModules[right].ManifestPath
		}
		if orderedModules[left].Path != orderedModules[right].Path {
			return orderedModules[left].Path < orderedModules[right].Path
		}
		return orderedModules[left].Dir < orderedModules[right].Dir
	})
	knownModuleDirs := make(map[string]bool, len(orderedModules))
	for _, module := range orderedModules {
		knownModuleDirs[canonicalPathForConfinement(module.Dir)] = true
	}

	pathValue, err := safeGoCommandPath(root)
	if err != nil {
		inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(
			root,
			"go_packages_unsafe_tool_path",
			"warning",
			fmt.Sprintf("go/packages was not invoked: %v; the static parser inventory was retained", err),
		))
		return inventory
	}

	commandEnvironment, err := constrainedGoEnvironment(root, pathValue)
	if err != nil {
		inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(
			root,
			"go_packages_environment",
			"warning",
			fmt.Sprintf("go/packages was not invoked: %v; the static parser inventory was retained", err),
		))
		return inventory
	}
	defer commandEnvironment.cleanup()
	baseEnvironment := commandEnvironment.Values
	dependencySnapshot.setModuleCache(commandEnvironment.ModuleCache)

	workPath, workSafe, workReason := confinedWorkFile(root, work)
	sourceWorkPath := workPath
	workspaceFallback := false
	if !workSafe && work.Path != "" {
		workspaceFallback = true
		inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(
			root,
			"go_packages_workspace_disabled",
			"warning",
			workReason+"; go/packages was not invoked for parsed workspace members, independent modules continue with GOWORK=off, and the parser retained workspace syntax",
		))
		workPath = ""
		sourceWorkPath = lexicalWorkspacePath(root, work.Path)
	}
	modulePreflights := make(map[string]goModulePreflight, len(orderedModules))
	for _, module := range orderedModules {
		if module.ManifestPath == "" {
			continue
		}
		if reason := moduleUnsafeForGoPackages(root, module, knownModuleDirs); reason != "" {
			modulePreflights[canonicalPathForConfinement(module.Dir)] = goModulePreflight{Code: "go_packages_module_confined_fallback", Reason: reason}
			continue
		}
		if reason := moduleSourceConfinementIssue(module, knownModuleDirs); reason != "" {
			modulePreflights[canonicalPathForConfinement(module.Dir)] = goModulePreflight{Code: "go_packages_source_confinement", Reason: reason}
		}
	}
	propagateUnsafeLocalReplacements(root, orderedModules, modulePreflights)
	if !workSafe && sourceWorkPath != "" {
		disableWorkspaceTypedLoading(root, orderedModules, work, sourceWorkPath, modulePreflights, workReason)
	} else if sourceWorkPath != "" {
		workspaceFailure := ""
		for _, module := range orderedModules {
			if !moduleIsWorkspaceMember(root, module, work, sourceWorkPath) {
				continue
			}
			if preflight := modulePreflights[canonicalPathForConfinement(module.Dir)]; preflight.Reason != "" {
				workspaceFailure = "a workspace member is unsafe for typed loading: " + preflight.Reason
				break
			}
		}
		if workspaceFailure == "" {
			if reason := workspaceModulesUnsafeForGoPackages(root, orderedModules, work, sourceWorkPath, knownModuleDirs); reason != "" {
				workspaceFailure = "go.work could not be isolated safely: " + reason
			}
		}
		if workspaceFailure == "" {
			if reason := unsafeWorkspaceReplacementReason(root, work, sourceWorkPath, modulePreflights); reason != "" {
				workspaceFailure = "go.work replacement is unsafe for typed loading: " + reason
			}
		}
		if workspaceFailure != "" {
			workspaceFallback = true
			inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(
				root,
				"go_packages_workspace_disabled",
				"warning",
				workspaceFailure+"; go/packages was not invoked for workspace members and the parser retained workspace syntax",
			))
			disableWorkspaceTypedLoading(root, orderedModules, work, sourceWorkPath, modulePreflights, workspaceFailure)
			workPath = ""
		}
	}
	var removeIsolatedWork func()
	if workPath != "" {
		workPath, removeIsolatedWork, err = isolatedGoWorkFile(root, work, sourceWorkPath)
		if err != nil {
			workspaceFailure := "go.work could not be isolated outside the scan root: " + err.Error()
			workspaceFallback = true
			inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(
				root,
				"go_packages_workspace_disabled",
				"warning",
				workspaceFailure+"; go/packages was not invoked for workspace members and the parser retained workspace syntax",
			))
			disableWorkspaceTypedLoading(root, orderedModules, work, sourceWorkPath, modulePreflights, workspaceFailure)
			workPath = ""
			removeIsolatedWork = nil
		} else {
			defer removeIsolatedWork()
		}
	}

	loadedModules := 0
	completeModules := 0
	failedModules := 0
	packageIDs := map[string]bool{}
	activeFiles := map[string]bool{}
	compiledFiles := map[string]bool{}
	embedFiles := map[string]bool{}
	testVariants := map[string]bool{}
	packageErrorCount := 0
	packageErrorsTruncated := false
	seenPackageErrors := map[string]bool{}

	for _, module := range orderedModules {
		if module.ManifestPath == "" {
			continue
		}
		if preflight := modulePreflights[canonicalPathForConfinement(module.Dir)]; preflight.Reason != "" {
			failedModules++
			inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
				Code:        preflight.Code,
				Severity:    "warning",
				Message:     normalizeGoPackagesMessage(root, preflight.Reason+"; go/packages was not invoked and the static parser inventory was retained for this module"),
				Path:        relativePath(root, module.ManifestPath),
				Recoverable: true,
			})
			continue
		}
		moduleWork := "off"
		if workSafe && workPath != "" && moduleIsWorkspaceMember(root, module, work, sourceWorkPath) {
			moduleWork = workPath
		}
		environment := append([]string{}, baseEnvironment...)
		environment = append(environment, "GOWORK="+moduleWork)

		loadContext, cancel := context.WithTimeout(context.Background(), timeout)
		config := &packages.Config{
			Context: loadContext,
			Dir:     module.Dir,
			Env:     environment,
			Mode: packages.NeedName |
				packages.NeedFiles |
				packages.NeedCompiledGoFiles |
				packages.NeedImports |
				packages.NeedDeps |
				packages.NeedModule |
				packages.NeedForTest |
				packages.NeedEmbedFiles |
				packages.NeedSyntax |
				packages.NeedTypes |
				packages.NeedTypesInfo |
				packages.NeedTypesSizes,
			Tests: true,
		}
		if len(tags) > 0 {
			config.BuildFlags = []string{"-tags=" + strings.Join(tags, ",")}
		}
		loaded, loadErr := loader(config, "./...")
		loadContextErr := loadContext.Err()
		cancel()
		if errors.Is(loadContextErr, context.DeadlineExceeded) || errors.Is(loadErr, context.DeadlineExceeded) {
			failedModules++
			inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
				Code:        "go_packages_load_timeout",
				Severity:    "warning",
				Message:     "go/packages typed load timed out under offline/read-only constraints; the static parser inventory was retained",
				Path:        relativePath(root, module.ManifestPath),
				Recoverable: true,
			})
			continue
		}
		if loadErr != nil {
			failedModules++
			message := "go/packages typed load failed under offline/read-only constraints: " + normalizeGoPackagesMessage(root, loadErr.Error(), workPath, filepath.Dir(workPath), commandEnvironment.NeutralRoot)
			inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
				Code:        "go_packages_load_failed",
				Severity:    "warning",
				Message:     message,
				Path:        relativePath(root, module.ManifestPath),
				Recoverable: true,
			})
			continue
		}
		loadedModules++
		moduleIncomplete := false
		moduleTypedPackages := make([]goTypedPackage, 0, len(loaded))
		sort.Slice(loaded, func(left, right int) bool {
			if loaded[left] == nil {
				return loaded[right] != nil
			}
			if loaded[right] == nil {
				return false
			}
			return loaded[left].ID < loaded[right].ID
		})

		for _, pkg := range loaded {
			if pkg == nil {
				continue
			}
			localPackage := packageBelongsToModule(root, module, pkg)
			if localPackage {
				packageKey := module.RelativeDir + "\x00" + pkg.ID
				packageIDs[packageKey] = true
				if pkg.ForTest != "" {
					testVariants[packageKey] = true
				}
				for _, file := range pkg.GoFiles {
					if confined, ok := confinedMetadataFile(root, file); ok {
						activeFiles[confined] = true
					}
				}
				for _, file := range pkg.CompiledGoFiles {
					if confined, ok := confinedMetadataFile(root, file); ok {
						compiledFiles[confined] = true
					}
				}
				for _, file := range pkg.EmbedFiles {
					if confined, ok := confinedMetadataFile(root, file); ok {
						embedFiles[confined] = true
					}
				}
				typedPackage, typedErr := collectGoTypedPackage(root, module, pkg)
				if typedErr != nil {
					moduleIncomplete = true
					message := fmt.Sprintf("package %q has incomplete typed data: %v", pkg.ID, typedErr)
					errorKey := module.ManifestPath + "\x00" + message
					if !seenPackageErrors[errorKey] {
						seenPackageErrors[errorKey] = true
						if packageErrorCount < maxGoPackagesErrors {
							packageErrorCount++
							inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
								Code:        "go_packages_typed_incomplete",
								Severity:    "warning",
								Message:     "go/packages reported incomplete typed data: " + normalizeGoPackagesMessage(root, message, workPath, filepath.Dir(workPath), commandEnvironment.NeutralRoot),
								Path:        relativePath(root, module.ManifestPath),
								Recoverable: true,
							})
						} else {
							packageErrorsTruncated = true
						}
					}
				} else {
					moduleTypedPackages = append(moduleTypedPackages, typedPackage)
				}
			}
			if len(pkg.Errors) > 0 {
				moduleIncomplete = true
				messages := make([]string, 0, len(pkg.Errors))
				for _, packageErr := range pkg.Errors {
					messages = append(messages, normalizeGoPackagesError(root, packageErr, workPath, filepath.Dir(workPath), commandEnvironment.NeutralRoot))
				}
				sort.Strings(messages)
				for _, message := range messages {
					errorKey := module.ManifestPath + "\x00" + message
					if seenPackageErrors[errorKey] {
						continue
					}
					seenPackageErrors[errorKey] = true
					if packageErrorCount >= maxGoPackagesErrors {
						packageErrorsTruncated = true
						break
					}
					packageErrorCount++
					inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
						Code:        "go_packages_package_error",
						Severity:    "warning",
						Message:     "go/packages reported incomplete offline metadata: " + message,
						Path:        relativePath(root, module.ManifestPath),
						Recoverable: true,
					})
				}
			}
			if localPackage {
				importPaths := make([]string, 0, len(pkg.Imports))
				for importPath := range pkg.Imports {
					importPaths = append(importPaths, importPath)
				}
				sort.Strings(importPaths)
				for _, importPath := range importPaths {
					imported := pkg.Imports[importPath]
					if importPath == "C" || (imported != nil && len(imported.GoFiles) > 0) {
						continue
					}
					message := fmt.Sprintf("import %q has no source metadata under offline constraints", importPath)
					errorKey := module.ManifestPath + "\x00" + message
					if seenPackageErrors[errorKey] {
						continue
					}
					seenPackageErrors[errorKey] = true
					moduleIncomplete = true
					if packageErrorCount >= maxGoPackagesErrors {
						packageErrorsTruncated = true
						continue
					}
					packageErrorCount++
					inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
						Code:        "go_packages_package_error",
						Severity:    "warning",
						Message:     "go/packages reported incomplete offline metadata: " + message,
						Path:        relativePath(root, module.ManifestPath),
						Recoverable: true,
					})
				}
			}
		}
		if reasons := dependencySnapshot.observeModuleLoad(module, loaded); len(reasons) > 0 {
			moduleIncomplete = true
			inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
				Code:        "go_dependency_snapshot_incomplete",
				Severity:    "warning",
				Message:     "offline dependency source snapshot was incomplete (" + strings.Join(reasons, ",") + "); typed packages for this module were discarded",
				Path:        relativePath(root, module.ManifestPath),
				Recoverable: true,
			})
		}
		if moduleIncomplete {
			failedModules++
			inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
				Code:        "go_packages_module_fallback",
				Severity:    "warning",
				Message:     "go/packages typed data was incomplete for this module; its typed packages were discarded and the static parser inventory was retained",
				Path:        relativePath(root, module.ManifestPath),
				Recoverable: true,
			})
		} else {
			completeModules++
			ssaInput := &goSSAInput{
				ModulePath:        module.Path,
				ModuleRelativeDir: module.RelativeDir,
				Roots:             append([]*packages.Package(nil), loaded...),
			}
			for index := range moduleTypedPackages {
				moduleTypedPackages[index].SSAInput = ssaInput
			}
			inventory.TypedPackages = append(inventory.TypedPackages, moduleTypedPackages...)
		}
	}
	sort.SliceStable(inventory.TypedPackages, func(left, right int) bool {
		leftPackage := inventory.TypedPackages[left]
		rightPackage := inventory.TypedPackages[right]
		if leftPackage.ModuleRelativeDir != rightPackage.ModuleRelativeDir {
			return leftPackage.ModuleRelativeDir < rightPackage.ModuleRelativeDir
		}
		if leftPackage.ModulePath != rightPackage.ModulePath {
			return leftPackage.ModulePath < rightPackage.ModulePath
		}
		if leftPackage.ID != rightPackage.ID {
			return leftPackage.ID < rightPackage.ID
		}
		if leftPackage.PkgPath != rightPackage.PkgPath {
			return leftPackage.PkgPath < rightPackage.PkgPath
		}
		return leftPackage.ForTest < rightPackage.ForTest
	})

	inventory.ModuleCount = loadedModules
	inventory.PackageCount = len(packageIDs)
	inventory.ActiveFileCount = len(activeFiles)
	inventory.CompiledFileCount = len(compiledFiles)
	inventory.EmbedFileCount = len(embedFiles)
	inventory.TestVariantCount = len(testVariants)
	if packageErrorsTruncated {
		inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(
			root,
			"go_packages_errors_truncated",
			"warning",
			fmt.Sprintf("go/packages diagnostics were limited to %d entries", maxGoPackagesErrors),
		))
	}

	switch {
	case completeModules > 0 && failedModules == 0 && !workspaceFallback:
		inventory.Status = "loaded"
		inventory.Fallback = false
	case completeModules > 0:
		inventory.Status = "partial"
		inventory.Fallback = true
	default:
		inventory.Status = "fallback"
		inventory.Fallback = true
	}
	return inventory
}

func collectGoTypedPackage(root string, module Module, pkg *packages.Package) (goTypedPackage, error) {
	if pkg.Fset == nil {
		return goTypedPackage{}, errors.New("file set is unavailable")
	}
	if pkg.Types == nil {
		return goTypedPackage{}, errors.New("Types is unavailable")
	}
	if pkg.TypesInfo == nil {
		return goTypedPackage{}, errors.New("TypesInfo is unavailable")
	}
	if pkg.TypesSizes == nil {
		return goTypedPackage{}, errors.New("TypesSizes is unavailable")
	}
	if pkg.IllTyped && len(pkg.Errors) == 0 {
		return goTypedPackage{}, errors.New("package is ill-typed without a package diagnostic")
	}

	files := make([]goTypedFile, 0, len(pkg.Syntax))
	seenFiles := make(map[string]bool, len(pkg.Syntax))
	for _, syntax := range pkg.Syntax {
		if syntax == nil {
			return goTypedPackage{}, errors.New("syntax contains a nil file")
		}
		position := pkg.Fset.PositionFor(syntax.Pos(), false)
		confined, ok := confinedMetadataFile(root, position.Filename)
		if !ok || !isWithinRoot(module.Dir, confined) {
			return goTypedPackage{}, fmt.Errorf("syntax file %q is not confined to the module", position.Filename)
		}
		path := relativePath(root, confined)
		if seenFiles[path] {
			return goTypedPackage{}, fmt.Errorf("syntax file %q is duplicated", path)
		}
		seenFiles[path] = true
		files = append(files, goTypedFile{Path: path, Syntax: syntax})
	}
	if len(pkg.CompiledGoFiles) > 0 && len(files) != len(pkg.CompiledGoFiles) {
		return goTypedPackage{}, fmt.Errorf("syntax file count %d does not match compiled file count %d", len(files), len(pkg.CompiledGoFiles))
	}
	sort.SliceStable(files, func(left, right int) bool {
		return files[left].Path < files[right].Path
	})

	return goTypedPackage{
		ModulePath:        module.Path,
		ModuleRelativeDir: module.RelativeDir,
		ID:                pkg.ID,
		PkgPath:           pkg.PkgPath,
		Name:              pkg.Name,
		ForTest:           pkg.ForTest,
		Files:             files,
		FileSet:           pkg.Fset,
		Types:             pkg.Types,
		TypesInfo:         pkg.TypesInfo,
		TypesSizes:        pkg.TypesSizes,
	}, nil
}

func moduleSourceConfinementIssue(module Module, knownModuleDirs map[string]bool) string {
	var issue string
	err := filepath.WalkDir(module.Dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			issue = fmt.Sprintf("symlink %q is not eligible for typed loading in safe mode", filepath.ToSlash(relativePath(module.Dir, path)))
			return fs.SkipAll
		}
		if entry.IsDir() && path != module.Dir {
			if knownModuleDirs[canonicalPathForConfinement(path)] {
				return fs.SkipDir
			}
			if entry.Name() == ".git" || entry.Name() == ".hg" || entry.Name() == ".svn" {
				return fs.SkipDir
			}
		}
		return nil
	})
	if issue != "" {
		return issue
	}
	if err != nil {
		return "module source confinement preflight failed: " + err.Error()
	}
	return ""
}

func safeGoCommandPath(root string) (string, error) {
	goCommand, err := exec.LookPath("go")
	if err != nil {
		return "", errors.New("the Go command is unavailable")
	}
	goCommand, err = filepath.Abs(goCommand)
	if err != nil {
		return "", errors.New("the Go command path could not be normalized")
	}
	resolved, err := filepath.EvalSymlinks(goCommand)
	if err != nil {
		return "", errors.New("the Go command path could not be resolved")
	}
	if isWithinRoot(root, filepath.Clean(resolved)) {
		return "", errors.New("PATH resolves the Go command from inside the scan root")
	}

	goDirectory := filepath.Dir(filepath.Clean(goCommand))
	resolvedDirectory := filepath.Dir(filepath.Clean(resolved))
	if !filepath.IsAbs(goDirectory) || isWithinRoot(root, goDirectory) || isWithinRoot(root, resolvedDirectory) ||
		strings.ContainsRune(goDirectory, os.PathListSeparator) || strings.ContainsRune(resolvedDirectory, os.PathListSeparator) {
		return "", errors.New("the resolved Go command directory is not safe")
	}
	entries := []string{goDirectory}
	for _, entry := range safePathEntries(root, os.Getenv("PATH")) {
		if entry != goDirectory {
			entries = append(entries, entry)
		}
	}
	return strings.Join(entries, string(os.PathListSeparator)), nil
}

func safePathEntries(root, rawPath string) []string {
	canonicalRoot := filepath.Clean(root)
	if resolved, err := filepath.EvalSymlinks(canonicalRoot); err == nil {
		canonicalRoot = filepath.Clean(resolved)
	}
	seen := map[string]bool{}
	var entries []string
	for _, entry := range filepath.SplitList(rawPath) {
		if entry == "" || !filepath.IsAbs(entry) {
			continue
		}
		clean := filepath.Clean(entry)
		resolved, err := filepath.EvalSymlinks(clean)
		if err != nil {
			continue
		}
		resolved = filepath.Clean(resolved)
		if isWithinRoot(canonicalRoot, resolved) || strings.ContainsRune(resolved, os.PathListSeparator) || seen[resolved] {
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.IsDir() {
			continue
		}
		seen[resolved] = true
		entries = append(entries, resolved)
	}
	return entries
}

func constrainedGoEnvironment(root, pathValue string) (goCommandEnvironment, error) {
	temporaryRoot := canonicalPathForConfinement(os.TempDir())
	if temporaryRoot == "" || !filepath.IsAbs(temporaryRoot) || isWithinRoot(root, temporaryRoot) {
		return goCommandEnvironment{}, errors.New("no neutral temporary directory is available outside the scan root")
	}
	neutralRoot, err := os.MkdirTemp(temporaryRoot, "depgraph-go-env-")
	if err != nil {
		return goCommandEnvironment{}, fmt.Errorf("create neutral Go environment: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(neutralRoot) }
	neutralRoot = canonicalPathForConfinement(neutralRoot)
	if neutralRoot == "" || !filepath.IsAbs(neutralRoot) || isWithinRoot(root, neutralRoot) || strings.ContainsRune(neutralRoot, os.PathListSeparator) {
		cleanup()
		return goCommandEnvironment{}, errors.New("the neutral Go environment is not outside the scan root")
	}

	home := filepath.Join(neutralRoot, "home")
	configRoot := filepath.Join(neutralRoot, "config")
	gocache := filepath.Join(neutralRoot, "build-cache")
	temporary := filepath.Join(neutralRoot, "tmp")
	gopathEntries := safePathListEnvironmentValues(root, "GOPATH")
	if len(gopathEntries) == 0 {
		if userHome, homeErr := os.UserHomeDir(); homeErr == nil {
			if defaultGoPath := confinedExternalEndpoint(root, filepath.Join(userHome, "go")); defaultGoPath != "" && !strings.ContainsRune(defaultGoPath, os.PathListSeparator) {
				gopathEntries = []string{defaultGoPath}
			}
		}
		if len(gopathEntries) == 0 {
			gopathEntries = []string{filepath.Join(neutralRoot, "gopath")}
		}
	}
	gopath := strings.Join(gopathEntries, string(os.PathListSeparator))
	gomodcache := safePathEnvironmentValue(root, "GOMODCACHE")
	if gomodcache == "" {
		gomodcache = confinedExternalEndpoint(root, filepath.Join(gopathEntries[0], "pkg", "mod"))
	}
	if gomodcache == "" {
		gomodcache = filepath.Join(neutralRoot, "module-cache")
	}
	for _, directory := range []string{home, configRoot, gocache, temporary, filepath.Join(neutralRoot, "gopath"), filepath.Join(neutralRoot, "module-cache")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			cleanup()
			return goCommandEnvironment{}, fmt.Errorf("create neutral Go directory: %w", err)
		}
	}
	telemetryModePath := filepath.Join(goUserConfigDir(home, configRoot), "go", "telemetry", "mode")
	if err := os.MkdirAll(filepath.Dir(telemetryModePath), 0o700); err != nil {
		cleanup()
		return goCommandEnvironment{}, fmt.Errorf("create isolated telemetry directory: %w", err)
	}
	if err := os.WriteFile(telemetryModePath, []byte("off 2000-01-01"), 0o600); err != nil {
		cleanup()
		return goCommandEnvironment{}, fmt.Errorf("disable Go telemetry: %w", err)
	}

	environment := []string{
		"PATH=" + pathValue,
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + configRoot,
		"USERPROFILE=" + home,
		"APPDATA=" + configRoot,
		"LOCALAPPDATA=" + filepath.Join(configRoot, "local"),
		"home=" + home,
		"GOPATH=" + gopath,
		"GOMODCACHE=" + gomodcache,
		"GOCACHE=" + gocache,
		"TMPDIR=" + temporary,
		"TEMP=" + temporary,
		"TMP=" + temporary,
		"GOOS=" + runtime.GOOS,
		"GOARCH=" + runtime.GOARCH,
		"CGO_ENABLED=0",
		"GO111MODULE=on",
		"GOENV=off",
		"GOFLAGS=-mod=readonly",
		"GOPACKAGESDRIVER=off",
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOVCS=*:off",
		"GOTOOLCHAIN=local",
	}
	if value := os.Getenv("PATHEXT"); value != "" {
		environment = append(environment, "PATHEXT="+value)
	}
	for _, key := range []string{"SYSTEMROOT", "WINDIR", "COMSPEC"} {
		if value := safePathEnvironmentValue(root, key); value != "" {
			environment = append(environment, key+"="+value)
		}
	}
	return goCommandEnvironment{
		Values: environment, NeutralRoot: neutralRoot, TelemetryModePath: telemetryModePath, ModuleCache: gomodcache, cleanup: cleanup,
	}, nil
}

func confinedExternalEndpoint(root, path string) string {
	canonical := canonicalPathForConfinement(path)
	if canonical == "" || !filepath.IsAbs(canonical) || isWithinRoot(root, canonical) {
		return ""
	}
	return canonical
}

func goUserConfigDir(home, configRoot string) string {
	switch runtime.GOOS {
	case "darwin", "ios":
		return filepath.Join(home, "Library", "Application Support")
	case "windows":
		return configRoot
	case "plan9":
		return filepath.Join(home, "lib")
	default:
		return configRoot
	}
}

func safePathEnvironmentValue(root, key string) string {
	value := os.Getenv(key)
	if value == "" || !filepath.IsAbs(value) {
		return ""
	}
	clean := canonicalPathForConfinement(value)
	if isWithinRoot(root, clean) {
		return ""
	}
	return clean
}

func safePathListEnvironmentValues(root, key string) []string {
	seen := map[string]bool{}
	var result []string
	for _, value := range filepath.SplitList(os.Getenv(key)) {
		if value == "" || !filepath.IsAbs(value) {
			continue
		}
		clean := canonicalPathForConfinement(value)
		if clean == "" || strings.ContainsRune(clean, os.PathListSeparator) || isWithinRoot(root, clean) || seen[clean] {
			continue
		}
		seen[clean] = true
		result = append(result, clean)
	}
	return result
}

// canonicalPathForConfinement resolves symlinks even when the final path does
// not exist by resolving its closest existing ancestor first.
func canonicalPathForConfinement(path string) string {
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	current := filepath.Clean(path)
	var suffix []string
	for {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			resolved = filepath.Clean(resolved)
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return filepath.Clean(path)
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func confinedWorkFile(root string, work WorkFile) (string, bool, string) {
	if work.Path == "" {
		return "", true, ""
	}
	resolved, err := resolveRegularFileWithinRoot(root, work.Path)
	if err != nil {
		return "", false, "go.work is not a confined regular file"
	}
	lexical, err := filepath.Abs(work.Path)
	if err != nil || filepath.Clean(lexical) != resolved {
		return "", false, "go.work symlinks are not eligible for typed loading in safe mode"
	}
	content, err := os.ReadFile(resolved)
	if err != nil {
		return "", false, "go.work could not be read safely"
	}
	official, err := modfile.ParseWork(resolved, content, nil)
	if err != nil {
		return "", false, "go.work failed official syntax validation"
	}
	if work.ParseIssues > 0 || !workFileMatchesOfficial(work, official) {
		return "", false, "go.work differs between the inventory and official parsers"
	}
	workDir := filepath.Dir(resolved)
	for _, use := range official.Use {
		candidate := use.Path
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(workDir, filepath.FromSlash(candidate))
		}
		candidate = canonicalPathForConfinement(candidate)
		if candidate == "" || !isWithinRoot(root, candidate) {
			return "", false, fmt.Sprintf("go.work use path %q is outside the scan root", use.Path)
		}
	}
	base := Module{Dir: workDir}
	for _, replacement := range official.Replace {
		if _, _, reason := resolveLocalReplacement(root, base, Replacement{
			OldPath: replacement.Old.Path, OldVersion: replacement.Old.Version,
			NewPath: replacement.New.Path, NewVersion: replacement.New.Version,
		}); reason != "" {
			return "", false, reason
		}
	}
	return resolved, true, ""
}

func lexicalWorkspacePath(root, path string) string {
	if path == "" {
		return ""
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	absolute = filepath.Clean(absolute)
	if !isWithinRoot(root, absolute) {
		return ""
	}
	return absolute
}

func workFileMatchesOfficial(work WorkFile, official *modfile.WorkFile) bool {
	if official.Go == nil || official.Go.Version != work.GoVersion || len(official.Godebug) != 0 {
		return false
	}
	toolchain := ""
	if official.Toolchain != nil {
		toolchain = official.Toolchain.Name
	}
	if toolchain != work.Toolchain || len(official.Use) != len(work.Uses) || len(official.Replace) != len(work.Replacements) {
		return false
	}
	uses := append([]string(nil), work.Uses...)
	officialUses := make([]string, 0, len(official.Use))
	for _, use := range official.Use {
		officialUses = append(officialUses, use.Path)
	}
	sort.Strings(uses)
	sort.Strings(officialUses)
	if strings.Join(uses, "\x00") != strings.Join(officialUses, "\x00") {
		return false
	}
	replacements := make([]string, 0, len(work.Replacements))
	for _, replacement := range work.Replacements {
		replacements = append(replacements, replacementKey(replacement))
	}
	officialReplacements := make([]string, 0, len(official.Replace))
	for _, replacement := range official.Replace {
		officialReplacements = append(officialReplacements, replacementKey(Replacement{
			OldPath: replacement.Old.Path, OldVersion: replacement.Old.Version,
			NewPath: replacement.New.Path, NewVersion: replacement.New.Version,
		}))
	}
	sort.Strings(replacements)
	sort.Strings(officialReplacements)
	return strings.Join(replacements, "\x00") == strings.Join(officialReplacements, "\x00")
}

func workspaceModulesUnsafeForGoPackages(root string, modules []Module, work WorkFile, sourceWorkPath string, knownModuleDirs map[string]bool) string {
	moduleCounts := make(map[string]int, len(modules))
	for _, module := range modules {
		moduleCounts[canonicalPathForConfinement(module.Dir)]++
	}
	workDir := filepath.Dir(sourceWorkPath)
	seenUses := map[string]bool{}
	for _, use := range work.Uses {
		candidate := use
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(workDir, filepath.FromSlash(candidate))
		}
		candidate = canonicalPathForConfinement(candidate)
		if candidate == "" || !isWithinRoot(root, candidate) || !knownModuleDirs[candidate] || moduleCounts[candidate] != 1 {
			return fmt.Sprintf("workspace use path %q does not identify exactly one discovered module", use)
		}
		if seenUses[candidate] {
			return fmt.Sprintf("workspace use path %q is duplicated", use)
		}
		seenUses[candidate] = true
	}
	base := Module{Dir: workDir}
	for _, replacement := range work.Replacements {
		target, local, reason := resolveLocalReplacement(root, base, replacement)
		if reason != "" {
			return reason
		}
		if local && (!knownModuleDirs[target] || moduleCounts[target] != 1) {
			return fmt.Sprintf("workspace replacement path %q does not identify exactly one discovered module", replacement.NewPath)
		}
	}
	return ""
}

func unsafeWorkspaceReplacementReason(root string, work WorkFile, sourceWorkPath string, preflights map[string]goModulePreflight) string {
	base := Module{Dir: filepath.Dir(sourceWorkPath)}
	for _, replacement := range work.Replacements {
		target, local, reason := resolveLocalReplacement(root, base, replacement)
		if reason != "" {
			return reason
		}
		if local {
			if preflight := preflights[target]; preflight.Reason != "" {
				return preflight.Reason
			}
		}
	}
	return ""
}

func disableWorkspaceTypedLoading(root string, modules []Module, work WorkFile, sourceWorkPath string, preflights map[string]goModulePreflight, reason string) {
	for _, module := range modules {
		if !moduleIsWorkspaceMember(root, module, work, sourceWorkPath) {
			continue
		}
		moduleDir := canonicalPathForConfinement(module.Dir)
		if preflights[moduleDir].Reason != "" {
			continue
		}
		preflights[moduleDir] = goModulePreflight{
			Code:   "go_packages_workspace_disabled",
			Reason: reason,
		}
	}
}

// isolatedGoWorkFile mirrors only the parsed, confinement-checked workspace
// directives into a neutral directory. The Go command may maintain go.work.sum
// beside GOWORK even in readonly module mode, so it must never receive the
// repository's original go.work path.
func isolatedGoWorkFile(root string, work WorkFile, sourceWorkPath string) (string, func(), error) {
	if work.GoVersion == "" || work.ParseIssues > 0 {
		return "", nil, errors.New("go.work is incomplete or contains unsupported directives")
	}
	temporaryRoot := canonicalPathForConfinement(os.TempDir())
	if temporaryRoot == "" || !filepath.IsAbs(temporaryRoot) || isWithinRoot(root, temporaryRoot) {
		return "", nil, errors.New("no neutral temporary directory is available outside the scan root")
	}
	directory, err := os.MkdirTemp(temporaryRoot, "depgraph-go-work-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	directory = canonicalPathForConfinement(directory)
	if directory == "" || isWithinRoot(root, directory) {
		cleanup()
		return "", nil, errors.New("isolated workspace directory is not outside the scan root")
	}

	workDir := filepath.Dir(sourceWorkPath)
	uses := make([]string, 0, len(work.Uses))
	for _, use := range work.Uses {
		candidate := use
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(workDir, filepath.FromSlash(candidate))
		}
		candidate = canonicalPathForConfinement(candidate)
		if candidate == "" || !isWithinRoot(root, candidate) {
			cleanup()
			return "", nil, fmt.Errorf("go.work use path %q could not be mirrored safely", use)
		}
		uses = append(uses, candidate)
	}
	sort.Strings(uses)

	isolated := &modfile.WorkFile{Syntax: &modfile.FileSyntax{Name: "go.work"}}
	if err := isolated.AddGoStmt(work.GoVersion); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("go.work go directive is invalid: %w", err)
	}
	if work.Toolchain != "" {
		if err := isolated.AddToolchainStmt(work.Toolchain); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("go.work toolchain directive is invalid: %w", err)
		}
	}
	for _, use := range uses {
		if err := isolated.AddUse(filepath.ToSlash(use), ""); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("go.work use directive could not be mirrored: %w", err)
		}
	}
	base := Module{Dir: workDir}
	expectedReplacements := make(map[string]bool, len(work.Replacements))
	for _, replacement := range work.Replacements {
		newPath := replacement.NewPath
		if localPath, local, reason := resolveLocalReplacement(root, base, replacement); reason != "" {
			cleanup()
			return "", nil, errors.New(reason)
		} else if local {
			newPath = filepath.ToSlash(localPath)
		}
		if err := isolated.AddReplace(replacement.OldPath, replacement.OldVersion, newPath, replacement.NewVersion); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("go.work replace directive could not be mirrored: %w", err)
		}
		expectedReplacements[replacementKey(Replacement{
			OldPath: replacement.OldPath, OldVersion: replacement.OldVersion,
			NewPath: newPath, NewVersion: replacement.NewVersion,
		})] = true
	}
	isolated.SortBlocks()
	content := modfile.Format(isolated.Syntax)
	validated, err := modfile.ParseWork("go.work", content, nil)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("isolated go.work validation failed: %w", err)
	}
	if validated.Go == nil || validated.Go.Version != work.GoVersion || len(validated.Godebug) != 0 {
		cleanup()
		return "", nil, errors.New("isolated go.work directives differ from the validated source model")
	}
	validatedToolchain := ""
	if validated.Toolchain != nil {
		validatedToolchain = validated.Toolchain.Name
	}
	if validatedToolchain != work.Toolchain || len(validated.Use) != len(uses) || len(validated.Replace) != len(expectedReplacements) {
		cleanup()
		return "", nil, errors.New("isolated go.work directives differ from the validated source model")
	}
	expectedUses := make(map[string]bool, len(uses))
	for _, use := range uses {
		expectedUses[filepath.ToSlash(use)] = true
	}
	for _, use := range validated.Use {
		candidate := filepath.Clean(filepath.FromSlash(use.Path))
		if !filepath.IsAbs(candidate) || !isWithinRoot(root, candidate) || !expectedUses[filepath.ToSlash(use.Path)] {
			cleanup()
			return "", nil, fmt.Errorf("isolated go.work use path %q is outside the scan root", use.Path)
		}
	}
	for _, replacement := range validated.Replace {
		key := replacementKey(Replacement{
			OldPath: replacement.Old.Path, OldVersion: replacement.Old.Version,
			NewPath: replacement.New.Path, NewVersion: replacement.New.Version,
		})
		if !expectedReplacements[key] {
			cleanup()
			return "", nil, errors.New("isolated go.work replacement directives differ from the validated source model")
		}
		if replacement.New.Version != "" {
			continue
		}
		candidate := filepath.Clean(filepath.FromSlash(replacement.New.Path))
		if !filepath.IsAbs(candidate) || !isWithinRoot(root, candidate) {
			cleanup()
			return "", nil, fmt.Errorf("isolated go.work replacement path %q is outside the scan root", replacement.New.Path)
		}
	}

	path := filepath.Join(directory, "go.work")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		cleanup()
		return "", nil, err
	}
	sourceSum := filepath.Join(workDir, "go.work.sum")
	if _, err := os.Lstat(sourceSum); err == nil {
		resolvedSum, err := resolveRegularFileWithinRoot(root, sourceSum)
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("go.work.sum could not be confined: %w", err)
		}
		sum, err := os.ReadFile(resolvedSum)
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("go.work.sum could not be read: %w", err)
		}
		if err := os.WriteFile(filepath.Join(directory, "go.work.sum"), sum, 0o600); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("go.work.sum could not be mirrored: %w", err)
		}
	} else if !os.IsNotExist(err) {
		cleanup()
		return "", nil, fmt.Errorf("go.work.sum could not be inspected: %w", err)
	}
	return path, cleanup, nil
}

func moduleUnsafeForGoPackages(root string, module Module, knownModuleDirs map[string]bool) string {
	resolvedManifest, err := resolveRegularFileWithinRoot(root, module.ManifestPath)
	if err != nil {
		return "go.mod is not a confined regular file"
	}
	moduleDir := canonicalPathForConfinement(module.Dir)
	if moduleDir == "" || !isWithinRoot(root, moduleDir) || filepath.Dir(resolvedManifest) != moduleDir {
		return "module directory is outside the scan root"
	}
	content, err := os.ReadFile(resolvedManifest)
	if err != nil {
		return "go.mod could not be read safely"
	}
	official, err := modfile.Parse(resolvedManifest, content, nil)
	if err != nil || official.Module == nil {
		return "go.mod failed official syntax validation"
	}
	if official.Module.Mod.Path != module.Path {
		return "go.mod differs between the inventory and official parsers"
	}
	base := module
	base.Dir = moduleDir
	for _, replacement := range official.Replace {
		target, local, reason := resolveLocalReplacement(root, base, Replacement{
			OldPath: replacement.Old.Path, OldVersion: replacement.Old.Version,
			NewPath: replacement.New.Path, NewVersion: replacement.New.Version,
		})
		if reason != "" {
			return reason
		}
		if local && !knownModuleDirs[target] {
			return fmt.Sprintf("local replacement %q does not identify a discovered module", replacement.New.Path)
		}
	}
	return ""
}

func propagateUnsafeLocalReplacements(root string, modules []Module, preflights map[string]goModulePreflight) {
	for changed := true; changed; {
		changed = false
		for _, module := range modules {
			moduleDir := canonicalPathForConfinement(module.Dir)
			if preflights[moduleDir].Reason != "" {
				continue
			}
			targets, err := moduleLocalReplacementTargets(root, module)
			if err != nil {
				preflights[moduleDir] = goModulePreflight{Code: "go_packages_module_confined_fallback", Reason: "go.mod local replacements could not be revalidated safely"}
				changed = true
				continue
			}
			for _, target := range targets {
				if targetPreflight := preflights[target]; targetPreflight.Reason != "" {
					preflights[moduleDir] = goModulePreflight{
						Code:   "go_packages_module_confined_fallback",
						Reason: "a local replacement reaches a module that is unsafe for typed loading: " + targetPreflight.Reason,
					}
					changed = true
					break
				}
			}
		}
	}
}

func moduleLocalReplacementTargets(root string, module Module) ([]string, error) {
	resolvedManifest, err := resolveRegularFileWithinRoot(root, module.ManifestPath)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(resolvedManifest)
	if err != nil {
		return nil, err
	}
	official, err := modfile.Parse(resolvedManifest, content, nil)
	if err != nil {
		return nil, err
	}
	base := module
	base.Dir = canonicalPathForConfinement(module.Dir)
	seen := map[string]bool{}
	var targets []string
	for _, replacement := range official.Replace {
		target, local, reason := resolveLocalReplacement(root, base, Replacement{
			OldPath: replacement.Old.Path, OldVersion: replacement.Old.Version,
			NewPath: replacement.New.Path, NewVersion: replacement.New.Version,
		})
		if reason != "" {
			return nil, errors.New(reason)
		}
		if local && !seen[target] {
			seen[target] = true
			targets = append(targets, target)
		}
	}
	sort.Strings(targets)
	return targets, nil
}

func moduleIsWorkspaceMember(root string, module Module, work WorkFile, sourceWorkPath string) bool {
	if sourceWorkPath == "" {
		return false
	}
	workDir := filepath.Dir(sourceWorkPath)
	for _, use := range work.Uses {
		candidate := use
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(workDir, filepath.FromSlash(candidate))
		}
		candidate = filepath.Clean(candidate)
		if evaluated, err := filepath.EvalSymlinks(candidate); err == nil {
			candidate = filepath.Clean(evaluated)
		}
		if isWithinRoot(root, candidate) && candidate == module.Dir {
			return true
		}
	}
	return false
}

func packageBelongsToModule(root string, module Module, pkg *packages.Package) bool {
	if pkg.Module != nil && pkg.Module.Dir != "" {
		dir := filepath.Clean(pkg.Module.Dir)
		if evaluated, err := filepath.EvalSymlinks(dir); err == nil {
			dir = filepath.Clean(evaluated)
		}
		if !isWithinRoot(root, dir) || dir != module.Dir {
			return false
		}
	}
	files := append([]string(nil), pkg.GoFiles...)
	files = append(files, pkg.CompiledGoFiles...)
	for _, file := range files {
		if confined, ok := confinedMetadataFile(root, file); ok && isWithinRoot(module.Dir, confined) {
			return true
		}
	}
	return false
}

func confinedMetadataFile(root, path string) (string, bool) {
	if path == "" || !filepath.IsAbs(path) {
		return "", false
	}
	resolved, err := resolveRegularFileWithinRoot(root, path)
	if err != nil {
		return "", false
	}
	return resolved, true
}

func goPackagesDiagnostic(root, code, severity, message string) Diagnostic {
	return Diagnostic{Code: code, Severity: severity, Message: normalizeGoPackagesMessage(root, message), Recoverable: true}
}

func normalizeGoPackagesError(root string, packageErr packages.Error, redactedPaths ...string) string {
	kind := "unknown"
	switch packageErr.Kind {
	case packages.ListError:
		kind = "list"
	case packages.ParseError:
		kind = "parse"
	case packages.TypeError:
		kind = "type"
	}
	message := packageErr.Msg
	if packageErr.Pos != "" {
		message = packageErr.Pos + ": " + message
	}
	return kind + ": " + normalizeGoPackagesMessage(root, message, redactedPaths...)
}

func normalizeGoPackagesMessage(root, message string, redactedPaths ...string) string {
	type pathReplacement struct {
		path        string
		replacement string
	}
	rootPath := filepath.Clean(root)
	var replacements []pathReplacement
	if filepath.Dir(rootPath) != rootPath {
		replacements = append(replacements, pathReplacement{path: rootPath, replacement: "."})
	}
	addPath := func(path, replacement string) {
		if path == "" || !filepath.IsAbs(path) {
			return
		}
		path = filepath.Clean(path)
		if filepath.Dir(path) == path {
			return
		}
		if path == rootPath {
			return
		}
		replacements = append(replacements, pathReplacement{path: path, replacement: replacement})
		if canonical := canonicalPathForConfinement(path); canonical != "" && canonical != path && canonical != rootPath {
			replacements = append(replacements, pathReplacement{path: canonical, replacement: replacement})
		}
	}
	addPath(runtime.GOROOT(), "$GOROOT")
	if home, err := os.UserHomeDir(); err == nil {
		addPath(home, "$HOME")
	}
	if cache, err := os.UserCacheDir(); err == nil {
		addPath(cache, "$CACHE")
	}
	addPath(os.TempDir(), "$TMP")
	for _, key := range []string{"GOMODCACHE", "GOCACHE", "TMPDIR", "TEMP", "TMP"} {
		addPath(os.Getenv(key), "$"+key)
	}
	for _, path := range filepath.SplitList(os.Getenv("GOPATH")) {
		addPath(path, "$GOPATH")
	}
	for index, path := range redactedPaths {
		if path == "" || path == "." {
			continue
		}
		label := "$ISOLATED_PATH"
		if index == 0 {
			label = "$GOWORK"
		}
		addPath(path, label)
	}
	sort.SliceStable(replacements, func(left, right int) bool {
		return len(replacements[left].path) > len(replacements[right].path)
	})
	for _, replacement := range replacements {
		message = strings.ReplaceAll(message, replacement.path, replacement.replacement)
	}
	message = strings.Join(strings.Fields(message), " ")
	const maximumLength = 4096
	if len(message) > maximumLength {
		message = message[:maximumLength] + "…"
	}
	return message
}

func inventoryProperties(inventory goPackagesInventory) map[string]string {
	typedFileCount := 0
	for _, pkg := range inventory.TypedPackages {
		typedFileCount += len(pkg.Files)
	}
	properties := map[string]string{
		"go_packages_status":                 inventory.Status,
		"go_packages_modules":                strconv.Itoa(inventory.ModuleCount),
		"go_packages_packages":               strconv.Itoa(inventory.PackageCount),
		"go_packages_active_files":           strconv.Itoa(inventory.ActiveFileCount),
		"go_packages_compiled_files":         strconv.Itoa(inventory.CompiledFileCount),
		"go_packages_embed_files":            strconv.Itoa(inventory.EmbedFileCount),
		"go_packages_test_variants":          strconv.Itoa(inventory.TestVariantCount),
		"go_packages_typed_packages":         strconv.Itoa(len(inventory.TypedPackages)),
		"go_packages_typed_files":            strconv.Itoa(typedFileCount),
		"go_packages_query":                  "syntax-types-types-info",
		"go_packages_safe_mode":              "offline,readonly,no-external-driver,cgo-disabled,telemetry-disabled",
		"go_dependency_snapshot_schema":      goDependencySnapshotSchema,
		"go_dependency_snapshot_status":      inventory.DependencySnapshot.Status,
		"go_dependency_snapshot_fingerprint": inventory.DependencySnapshot.Fingerprint,
		"go_dependency_snapshot_modules":     strconv.Itoa(inventory.DependencySnapshot.ModuleCount),
		"go_dependency_snapshot_packages":    strconv.Itoa(inventory.DependencySnapshot.PackageCount),
		"go_dependency_snapshot_files":       strconv.Itoa(inventory.DependencySnapshot.FileCount),
	}
	if len(inventory.DependencySnapshot.Reasons) > 0 {
		properties["go_dependency_snapshot_reasons"] = strings.Join(inventory.DependencySnapshot.Reasons, ",")
	}
	return properties
}
