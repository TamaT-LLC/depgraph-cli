package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/tools/go/packages"
)

const (
	goPackagesLoadTimeout = 30 * time.Second
	maxGoPackagesErrors   = 20
)

// goPackagesInventory is deliberately metadata-only. The standard-library
// parser remains the source of dependency sites, spans, and syntax coverage so
// a missing offline module cache cannot erase otherwise observable source.
type goPackagesInventory struct {
	Status            string
	ModuleCount       int
	PackageCount      int
	ActiveFileCount   int
	CompiledFileCount int
	EmbedFileCount    int
	TestVariantCount  int
	Fallback          bool
	Diagnostics       []Diagnostic
}

func loadGoPackagesInventory(root string, modules []Module, work WorkFile, tags []string) goPackagesInventory {
	inventory := goPackagesInventory{Status: "fallback", Fallback: true}
	if len(modules) == 0 || (len(modules) == 1 && modules[0].ManifestPath == "") {
		inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(
			root,
			"go_packages_no_module",
			"info",
			"go/packages was not invoked because no confined go.mod was discovered; the static parser inventory was retained",
		))
		return inventory
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

	baseEnvironment, err := constrainedGoEnvironment(root, pathValue)
	if err != nil {
		inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(
			root,
			"go_packages_environment",
			"warning",
			fmt.Sprintf("go/packages was not invoked: %v; the static parser inventory was retained", err),
		))
		return inventory
	}

	workPath, workSafe, workReason := confinedWorkFile(root, work)
	if !workSafe && work.Path != "" {
		inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(
			root,
			"go_packages_workspace_disabled",
			"warning",
			workReason+"; go/packages will inspect each confined module with GOWORK=off and the parser will retain workspace syntax",
		))
		inventory.Fallback = true
	}

	loadedModules := 0
	failedModules := 0
	packageIDs := map[string]bool{}
	activeFiles := map[string]bool{}
	compiledFiles := map[string]bool{}
	embedFiles := map[string]bool{}
	testVariants := map[string]bool{}
	packageErrorCount := 0
	seenPackageErrors := map[string]bool{}

	for _, module := range modules {
		if module.ManifestPath == "" {
			continue
		}
		if reason := moduleUnsafeForGoPackages(root, module); reason != "" {
			failedModules++
			inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
				Code:        "go_packages_module_confined_fallback",
				Severity:    "warning",
				Message:     reason + "; the static parser inventory was retained for this module",
				Path:        relativePath(root, module.ManifestPath),
				Recoverable: true,
			})
			continue
		}

		moduleWork := "off"
		if workSafe && workPath != "" && moduleIsWorkspaceMember(root, module, work) {
			moduleWork = workPath
		}
		environment := append([]string{}, baseEnvironment...)
		environment = append(environment, "GOWORK="+moduleWork)

		context, cancel := context.WithTimeout(context.Background(), goPackagesLoadTimeout)
		config := &packages.Config{
			Context: context,
			Dir:     module.Dir,
			Env:     environment,
			Mode: packages.NeedName |
				packages.NeedFiles |
				packages.NeedCompiledGoFiles |
				packages.NeedImports |
				packages.NeedDeps |
				packages.NeedModule |
				packages.NeedForTest |
				packages.NeedEmbedFiles,
			Tests: true,
		}
		if len(tags) > 0 {
			config.BuildFlags = []string{"-tags=" + strings.Join(tags, ",")}
		}
		loaded, loadErr := packages.Load(config, "./...")
		cancel()
		if loadErr != nil {
			failedModules++
			inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
				Code:        "go_packages_load_failed",
				Severity:    "warning",
				Message:     "go/packages metadata load failed under offline/read-only constraints: " + normalizeGoPackagesMessage(root, loadErr.Error()),
				Path:        relativePath(root, module.ManifestPath),
				Recoverable: true,
			})
			continue
		}
		loadedModules++
		moduleIncomplete := false
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
				packageIDs[pkg.ID] = true
				if pkg.ForTest != "" {
					testVariants[pkg.ID] = true
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
			}
			if len(pkg.Errors) > 0 {
				moduleIncomplete = true
				messages := make([]string, 0, len(pkg.Errors))
				for _, packageErr := range pkg.Errors {
					messages = append(messages, normalizeGoPackagesMessage(root, packageErr.Error()))
				}
				sort.Strings(messages)
				for _, message := range messages {
					errorKey := module.ManifestPath + "\x00" + message
					if seenPackageErrors[errorKey] {
						continue
					}
					seenPackageErrors[errorKey] = true
					if packageErrorCount >= maxGoPackagesErrors {
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
		if moduleIncomplete {
			failedModules++
		}
	}

	inventory.ModuleCount = loadedModules
	inventory.PackageCount = len(packageIDs)
	inventory.ActiveFileCount = len(activeFiles)
	inventory.CompiledFileCount = len(compiledFiles)
	inventory.EmbedFileCount = len(embedFiles)
	inventory.TestVariantCount = len(testVariants)
	if packageErrorCount == maxGoPackagesErrors {
		inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(
			root,
			"go_packages_errors_truncated",
			"warning",
			fmt.Sprintf("go/packages diagnostics were limited to %d entries", maxGoPackagesErrors),
		))
	}

	switch {
	case loadedModules > 0 && failedModules == 0:
		inventory.Status = "loaded"
		inventory.Fallback = false
	case loadedModules > 0:
		inventory.Status = "partial"
		inventory.Fallback = true
	default:
		inventory.Status = "fallback"
		inventory.Fallback = true
	}
	return inventory
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

	entries := safePathEntries(root, os.Getenv("PATH"))
	if len(entries) == 0 {
		return "", errors.New("PATH has no absolute directory outside the scan root")
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
		if isWithinRoot(canonicalRoot, resolved) || seen[resolved] {
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

func constrainedGoEnvironment(root, pathValue string) ([]string, error) {
	cacheRoot, err := os.UserCacheDir()
	cacheRoot = canonicalPathForConfinement(cacheRoot)
	if err != nil || cacheRoot == "" || !filepath.IsAbs(cacheRoot) || isWithinRoot(root, cacheRoot) {
		cacheRoot = os.TempDir()
	}
	cacheRoot = canonicalPathForConfinement(cacheRoot)
	if !filepath.IsAbs(cacheRoot) || isWithinRoot(root, cacheRoot) {
		return nil, errors.New("no neutral cache directory is available outside the scan root")
	}

	home, _ := os.UserHomeDir()
	home = canonicalPathForConfinement(home)
	if home == "" || !filepath.IsAbs(home) || isWithinRoot(root, home) {
		home = filepath.Join(cacheRoot, "depgraph", "go-home")
	}
	gopathEntries := safePathListEnvironmentValues(root, "GOPATH")
	if len(gopathEntries) == 0 {
		gopathEntries = []string{filepath.Join(home, "go")}
	}
	gopath := strings.Join(gopathEntries, string(os.PathListSeparator))
	gomodcache := safePathEnvironmentValue(root, "GOMODCACHE")
	if gomodcache == "" {
		gomodcache = filepath.Join(gopathEntries[0], "pkg", "mod")
	}
	gocache := safePathEnvironmentValue(root, "GOCACHE")
	if gocache == "" {
		gocache = filepath.Join(cacheRoot, "depgraph", "go-build")
	}
	temporary := safePathEnvironmentValue(root, "TMPDIR")
	if temporary == "" {
		temporary = safePathEnvironmentValue(root, "TEMP")
	}
	if temporary == "" {
		temporary = cacheRoot
	}

	goroot := canonicalPathForConfinement(runtime.GOROOT())
	if goroot == "" || !filepath.IsAbs(goroot) || isWithinRoot(root, goroot) {
		return nil, errors.New("the Go runtime root is unavailable outside the scan root")
	}

	environment := []string{
		"PATH=" + pathValue,
		"HOME=" + home,
		"GOPATH=" + gopath,
		"GOMODCACHE=" + gomodcache,
		"GOCACHE=" + gocache,
		"TMPDIR=" + temporary,
		"TEMP=" + temporary,
		"TMP=" + temporary,
		"GOROOT=" + goroot,
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
	for _, key := range []string{"SYSTEMROOT", "WINDIR", "COMSPEC", "USERPROFILE", "LOCALAPPDATA", "APPDATA"} {
		if value := safePathEnvironmentValue(root, key); value != "" {
			environment = append(environment, key+"="+value)
		}
	}
	return environment, nil
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
		if clean == "" || isWithinRoot(root, clean) || seen[clean] {
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
	workDir := filepath.Dir(resolved)
	for _, use := range work.Uses {
		candidate := use
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(workDir, filepath.FromSlash(candidate))
		}
		candidate = filepath.Clean(candidate)
		if evaluated, evalErr := filepath.EvalSymlinks(candidate); evalErr == nil {
			candidate = filepath.Clean(evaluated)
		}
		if !isWithinRoot(root, candidate) {
			return "", false, fmt.Sprintf("go.work use path %q is outside the scan root", use)
		}
	}
	base := Module{Dir: workDir}
	for _, replacement := range work.Replacements {
		if _, _, reason := resolveLocalReplacement(root, base, replacement); reason != "" {
			return "", false, reason
		}
	}
	return resolved, true, ""
}

func moduleUnsafeForGoPackages(root string, module Module) string {
	if _, err := resolveRegularFileWithinRoot(root, module.ManifestPath); err != nil {
		return "go.mod is not a confined regular file"
	}
	if !isWithinRoot(root, module.Dir) {
		return "module directory is outside the scan root"
	}
	for _, replacement := range module.Replacements {
		if _, _, reason := resolveLocalReplacement(root, module, replacement); reason != "" {
			return reason
		}
	}
	return ""
}

func moduleIsWorkspaceMember(root string, module Module, work WorkFile) bool {
	if work.Path == "" {
		return false
	}
	workDir := filepath.Dir(work.Path)
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
		return isWithinRoot(root, dir) && dir == module.Dir
	}
	for _, file := range pkg.GoFiles {
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

func normalizeGoPackagesMessage(root, message string) string {
	message = strings.ReplaceAll(message, filepath.Clean(root), ".")
	message = strings.Join(strings.Fields(message), " ")
	const maximumLength = 4096
	if len(message) > maximumLength {
		message = message[:maximumLength] + "…"
	}
	return message
}

func inventoryProperties(inventory goPackagesInventory) map[string]string {
	return map[string]string{
		"go_packages_status":         inventory.Status,
		"go_packages_modules":        strconv.Itoa(inventory.ModuleCount),
		"go_packages_packages":       strconv.Itoa(inventory.PackageCount),
		"go_packages_active_files":   strconv.Itoa(inventory.ActiveFileCount),
		"go_packages_compiled_files": strconv.Itoa(inventory.CompiledFileCount),
		"go_packages_embed_files":    strconv.Itoa(inventory.EmbedFileCount),
		"go_packages_test_variants":  strconv.Itoa(inventory.TestVariantCount),
		"go_packages_query":          "metadata-only-go-list",
		"go_packages_safe_mode":      "offline,readonly,no-external-driver,cgo-disabled",
	}
}
