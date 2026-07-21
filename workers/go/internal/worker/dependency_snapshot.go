package worker

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const (
	goDependencySnapshotSchema = "go-offline-dependency-snapshot-v1"
	maxDependencySnapshotFiles = 100_000
	maxDependencySnapshotBytes = int64(512 << 20)
	maxDependencySnapshotFile  = int64(64 << 20)
	maxDependencyManifestBytes = int64(8 << 20)
)

type goDependencySnapshot struct {
	Status       string
	Fingerprint  string
	ModuleCount  int
	PackageCount int
	FileCount    int
	Reasons      []string
}

type goDependencyDeclaration struct {
	Kind        string `json:"kind"`
	Owner       string `json:"owner"`
	Module      string `json:"module,omitempty"`
	Version     string `json:"version,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	Checksum    string `json:"checksum,omitempty"`
}

type goDependencySnapshotFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type goDependencySnapshotPackage struct {
	Module      string                     `json:"module"`
	Replacement string                     `json:"replacement,omitempty"`
	Source      string                     `json:"source"`
	Package     string                     `json:"package"`
	Checksums   []string                   `json:"checksums,omitempty"`
	Files       []goDependencySnapshotFile `json:"files"`
}

type goDependencySnapshotBuilder struct {
	root          string
	moduleCache   string
	modules       []Module
	declarations  []goDependencyDeclaration
	packages      map[string]goDependencySnapshotPackage
	checksums     map[string]map[string]bool
	reasons       map[string]bool
	activeReasons map[string]bool
	fileDigests   map[string]string
	observedBytes int64
	hasDependency bool
}

func (b *goDependencySnapshotBuilder) addReason(reason string) {
	b.reasons[reason] = true
	if b.activeReasons != nil {
		b.activeReasons[reason] = true
	}
}

func newGoDependencySnapshotBuilder(root string, modules []Module, work WorkFile) *goDependencySnapshotBuilder {
	builder := &goDependencySnapshotBuilder{
		root:        filepath.Clean(root),
		modules:     append([]Module(nil), modules...),
		packages:    map[string]goDependencySnapshotPackage{},
		checksums:   map[string]map[string]bool{},
		reasons:     map[string]bool{},
		fileDigests: map[string]string{},
	}
	builder.collectChecksumDeclarations(modules, work)
	builder.collectModuleDeclarations(modules, work)
	return builder
}

func (b *goDependencySnapshotBuilder) setModuleCache(path string) {
	b.moduleCache = canonicalPathForConfinement(path)
}

func (b *goDependencySnapshotBuilder) collectChecksumDeclarations(modules []Module, work WorkFile) {
	for _, module := range modules {
		if module.ManifestPath == "" {
			continue
		}
		b.collectChecksumFile(filepath.Join(module.Dir, "go.sum"), dependencySnapshotModuleOwner(module))
		vendorManifest := filepath.Join(module.Dir, "vendor", "modules.txt")
		if _, err := os.Lstat(vendorManifest); err == nil {
			digest, digestErr := dependencySnapshotRootFileDigest(b.root, vendorManifest, maxDependencyManifestBytes)
			if digestErr != nil {
				b.addReason("vendor-manifest-unreadable")
				continue
			}
			b.hasDependency = true
			b.declarations = append(b.declarations, goDependencyDeclaration{
				Kind: "vendor_manifest", Owner: dependencySnapshotModuleOwner(module), Checksum: digest,
			})
		}
	}
	if work.Path != "" {
		b.collectChecksumFile(filepath.Join(filepath.Dir(work.Path), "go.work.sum"), "go.work")
	}
}

func (b *goDependencySnapshotBuilder) collectChecksumFile(path, owner string) {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return
	} else if err != nil {
		b.addReason("dependency-checksum-unreadable")
		return
	}
	file, err := openDependencySnapshotManifest(b.root, path)
	if err != nil {
		b.addReason("dependency-checksum-unreadable")
		return
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, maxDependencyManifestBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(contents)) > maxDependencyManifestBytes {
		b.addReason("dependency-checksum-unreadable")
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(string(contents)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || !strings.HasPrefix(fields[2], "h1:") {
			continue
		}
		modulePath := fields[0]
		version := fields[1]
		key := modulePath + "@" + strings.TrimSuffix(version, "/go.mod")
		if b.checksums[key] == nil {
			b.checksums[key] = map[string]bool{}
		}
		checksum := version + "=" + fields[2]
		b.checksums[key][checksum] = true
		b.hasDependency = true
		b.declarations = append(b.declarations, goDependencyDeclaration{
			Kind: "checksum", Owner: owner, Module: modulePath, Version: version, Checksum: fields[2],
		})
	}
	if scanner.Err() != nil {
		b.addReason("dependency-checksum-unreadable")
	}
}

func (b *goDependencySnapshotBuilder) collectModuleDeclarations(modules []Module, work WorkFile) {
	for _, module := range modules {
		owner := dependencySnapshotModuleOwner(module)
		for _, requirement := range module.Requirements {
			b.hasDependency = true
			b.declarations = append(b.declarations, goDependencyDeclaration{
				Kind: "requirement", Owner: owner, Module: requirement.Path, Version: requirement.Version,
			})
		}
		for _, replacement := range module.Replacements {
			b.hasDependency = true
			b.declarations = append(b.declarations, goDependencyDeclaration{
				Kind: "replacement", Owner: owner, Module: replacement.OldPath, Version: replacement.OldVersion,
				Replacement: dependencySnapshotReplacement(b.root, module.Dir, replacement.NewPath, replacement.NewVersion),
			})
		}
	}
	workDir := filepath.Dir(work.Path)
	for _, replacement := range work.Replacements {
		b.hasDependency = true
		b.declarations = append(b.declarations, goDependencyDeclaration{
			Kind: "workspace_replacement", Owner: "go.work", Module: replacement.OldPath, Version: replacement.OldVersion,
			Replacement: dependencySnapshotReplacement(b.root, workDir, replacement.NewPath, replacement.NewVersion),
		})
	}
}

func dependencySnapshotModuleOwner(module Module) string {
	return module.Path + "@workspace#" + filepath.ToSlash(module.RelativeDir)
}

func dependencySnapshotReplacement(root, ownerDir, path, version string) string {
	if version != "" {
		return path + "@" + version
	}
	if path == "" {
		return ""
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(ownerDir, filepath.FromSlash(candidate))
	}
	candidate = canonicalPathForConfinement(candidate)
	if candidate != "" && isWithinRoot(root, candidate) {
		return "repo:" + filepath.ToSlash(relativePath(root, candidate))
	}
	if strings.HasPrefix(path, ".") || filepath.IsAbs(path) {
		return "unavailable:outside-root"
	}
	return path
}

func (b *goDependencySnapshotBuilder) observeModuleLoad(module Module, roots []*packages.Package) []string {
	moduleReasons := map[string]bool{}
	b.activeReasons = moduleReasons
	for _, pkg := range dependencySnapshotPackages(roots) {
		b.observePackage(module, pkg)
	}
	b.activeReasons = nil
	result := make([]string, 0, len(moduleReasons))
	for reason := range moduleReasons {
		result = append(result, reason)
	}
	sort.Strings(result)
	return result
}

func dependencySnapshotPackages(roots []*packages.Package) []*packages.Package {
	seen := map[*packages.Package]bool{}
	var result []*packages.Package
	var visit func(*packages.Package)
	visit = func(pkg *packages.Package) {
		if pkg == nil || seen[pkg] {
			return
		}
		seen[pkg] = true
		result = append(result, pkg)
		paths := make([]string, 0, len(pkg.Imports))
		for path := range pkg.Imports {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			visit(pkg.Imports[path])
		}
	}
	orderedRoots := append([]*packages.Package(nil), roots...)
	sort.SliceStable(orderedRoots, func(left, right int) bool {
		if orderedRoots[left] == nil {
			return orderedRoots[right] != nil
		}
		if orderedRoots[right] == nil {
			return false
		}
		return orderedRoots[left].ID < orderedRoots[right].ID
	})
	for _, root := range orderedRoots {
		visit(root)
	}
	return result
}

func (b *goDependencySnapshotBuilder) observePackage(module Module, pkg *packages.Package) {
	files := dependencySnapshotPackageFiles(pkg)
	vendorRoot := filepath.Join(module.Dir, "vendor")
	if dependencySnapshotAnyFileWithin(vendorRoot, files) {
		modulePath, version := b.vendorModuleForPackage(module, pkg.PkgPath)
		b.observePackageFiles(pkg, "vendor:"+modulePath+"@"+version, "", "vendor", vendorRoot, files)
		return
	}
	if dependencySnapshotCurrentModule(module, pkg) {
		return
	}
	if packageBelongsToModule(b.root, module, pkg) {
		return
	}
	if pkg.Module == nil {
		if looksLikeStandardLibrary(pkg.PkgPath) || dependencySnapshotAnyFileWithin(runtimeGoRoot(), files) {
			return
		}
		b.addReason("dependency-module-metadata-unavailable")
		return
	}
	if pkg.Module.Error != nil {
		b.addReason("dependency-module-metadata-error")
		return
	}
	original := dependencySnapshotModuleLocator(pkg.Module)
	effective := pkg.Module
	replacement := ""
	if pkg.Module.Replace != nil {
		effective = pkg.Module.Replace
		replacement = dependencySnapshotEffectiveReplacement(b.root, effective)
	}
	base := canonicalPathForConfinement(effective.Dir)
	if base == "" && pkg.Dir != "" {
		base = canonicalPathForConfinement(pkg.Dir)
	}
	source := "module-cache"
	if base != "" && isWithinRoot(b.root, base) {
		source = "local-replace"
		if replacement == "" {
			replacement = "repo:" + filepath.ToSlash(relativePath(b.root, base))
		}
	} else if base == "" || b.moduleCache == "" || !isWithinRoot(b.moduleCache, base) {
		b.addReason("dependency-source-outside-admitted-roots")
		return
	}
	b.observePackageFiles(pkg, original, replacement, source, base, files)
}

func dependencySnapshotCurrentModule(module Module, pkg *packages.Package) bool {
	if pkg == nil || pkg.Module == nil || pkg.Module.Path != module.Path {
		return false
	}
	effective := pkg.Module
	if effective.Replace != nil {
		effective = effective.Replace
	}
	return canonicalPathForConfinement(effective.Dir) == canonicalPathForConfinement(module.Dir)
}

func (b *goDependencySnapshotBuilder) observePackageFiles(
	pkg *packages.Package,
	module, replacement, source, base string,
	files []string,
) {
	if len(files) == 0 {
		b.addReason("dependency-package-source-unavailable")
		return
	}
	entry := goDependencySnapshotPackage{
		Module: module, Replacement: replacement, Source: source, Package: pkg.PkgPath,
		Checksums: b.moduleChecksums(strings.TrimPrefix(strings.TrimPrefix(module, "vendor:"), "module:")),
	}
	fileMap := map[string]string{}
	for _, file := range files {
		relative, digest, reason := b.fileDigest(base, file)
		if reason != "" {
			b.addReason(reason)
			continue
		}
		fileMap[relative] = digest
	}
	if len(fileMap) == 0 {
		b.addReason("dependency-package-source-unavailable")
		return
	}
	paths := make([]string, 0, len(fileMap))
	for path := range fileMap {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		entry.Files = append(entry.Files, goDependencySnapshotFile{Path: path, Digest: fileMap[path]})
	}
	key := entry.Module + "\x00" + entry.Replacement + "\x00" + entry.Source + "\x00" + entry.Package
	if existing, ok := b.packages[key]; ok {
		entry.Files = mergeDependencySnapshotFiles(existing.Files, entry.Files)
		entry.Checksums = mergeSortedStrings(existing.Checksums, entry.Checksums)
	}
	b.packages[key] = entry
	b.hasDependency = true
}

func dependencySnapshotPackageFiles(pkg *packages.Package) []string {
	seen := map[string]bool{}
	var files []string
	for _, candidates := range [][]string{pkg.GoFiles, pkg.CompiledGoFiles, pkg.OtherFiles, pkg.EmbedFiles} {
		for _, file := range candidates {
			file = filepath.Clean(file)
			if file == "." || seen[file] {
				continue
			}
			seen[file] = true
			files = append(files, file)
		}
	}
	sort.Strings(files)
	return files
}

func dependencySnapshotAnyFileWithin(root string, files []string) bool {
	root = canonicalPathForConfinement(root)
	if root == "" {
		return false
	}
	for _, file := range files {
		if candidate := canonicalPathForConfinement(file); candidate != "" && isWithinRoot(root, candidate) {
			return true
		}
	}
	return false
}

func runtimeGoRoot() string {
	return canonicalPathForConfinement(runtime.GOROOT())
}

func (b *goDependencySnapshotBuilder) vendorModuleForPackage(module Module, packagePath string) (string, string) {
	bestPath, bestVersion := "", "unknown"
	for _, candidate := range b.modules {
		if candidate.Dir != module.Dir {
			continue
		}
		for _, requirement := range candidate.Requirements {
			if (packagePath == requirement.Path || strings.HasPrefix(packagePath, requirement.Path+"/")) && len(requirement.Path) > len(bestPath) {
				bestPath, bestVersion = requirement.Path, requirement.Version
			}
		}
	}
	if bestPath == "" {
		bestPath = packagePath
	}
	return bestPath, bestVersion
}

func dependencySnapshotModuleLocator(module *packages.Module) string {
	if module == nil {
		return "module:unknown@unknown"
	}
	version := module.Version
	if version == "" {
		version = "workspace"
	}
	return "module:" + module.Path + "@" + version
}

func dependencySnapshotEffectiveReplacement(root string, module *packages.Module) string {
	if module == nil {
		return ""
	}
	if module.Version != "" {
		return module.Path + "@" + module.Version
	}
	dir := canonicalPathForConfinement(module.Dir)
	if dir != "" && isWithinRoot(root, dir) {
		return "repo:" + filepath.ToSlash(relativePath(root, dir))
	}
	return module.Path
}

func (b *goDependencySnapshotBuilder) moduleChecksums(locator string) []string {
	locator = strings.TrimSuffix(locator, "@workspace")
	values := b.checksums[locator]
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (b *goDependencySnapshotBuilder) fileDigest(base, path string) (string, string, string) {
	base = filepath.Clean(base)
	path = filepath.Clean(path)
	if base == "." || !filepath.IsAbs(base) || !filepath.IsAbs(path) || !isWithinRoot(base, path) {
		return "", "", "dependency-source-outside-module"
	}
	if canonicalPathForConfinement(base) != base || canonicalPathForConfinement(path) != path {
		return "", "", "dependency-source-symlink"
	}
	relative, err := filepath.Rel(base, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", "", "dependency-source-outside-module"
	}
	if digest, ok := b.fileDigests[path]; ok {
		return filepath.ToSlash(relative), digest, ""
	}
	if len(b.fileDigests) >= maxDependencySnapshotFiles {
		return "", "", "dependency-snapshot-file-limit"
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", "", "dependency-source-unreadable"
	}
	if info.Size() > maxDependencySnapshotFile || b.observedBytes+info.Size() > maxDependencySnapshotBytes {
		return "", "", "dependency-snapshot-byte-limit"
	}
	file, err := os.Open(path)
	if err != nil {
		return "", "", "dependency-source-unreadable"
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, io.LimitReader(file, maxDependencySnapshotFile+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written != info.Size() || written > maxDependencySnapshotFile {
		return "", "", "dependency-source-unreadable"
	}
	digest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	b.fileDigests[path] = digest
	b.observedBytes += written
	return filepath.ToSlash(relative), digest, ""
}

func dependencySnapshotRootFileDigest(root, path string, limit int64) (string, error) {
	file, err := openDependencySnapshotManifest(root, path)
	if err != nil {
		return "", err
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if int64(len(contents)) > limit {
		return "", fmt.Errorf("dependency manifest exceeds %d-byte limit", limit)
	}
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func openDependencySnapshotManifest(root, path string) (*os.File, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || canonicalPathForConfinement(clean) != clean {
		return nil, errors.New("dependency manifest is not a canonical regular file")
	}
	return openRegularFileWithinRoot(root, clean)
}

func mergeDependencySnapshotFiles(left, right []goDependencySnapshotFile) []goDependencySnapshotFile {
	values := map[string]string{}
	for _, file := range append(append([]goDependencySnapshotFile(nil), left...), right...) {
		values[file.Path] = file.Digest
	}
	paths := make([]string, 0, len(values))
	for path := range values {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	result := make([]goDependencySnapshotFile, 0, len(paths))
	for _, path := range paths {
		result = append(result, goDependencySnapshotFile{Path: path, Digest: values[path]})
	}
	return result
}

func mergeSortedStrings(left, right []string) []string {
	values := map[string]bool{}
	for _, value := range append(append([]string(nil), left...), right...) {
		values[value] = true
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (b *goDependencySnapshotBuilder) finalize(loadStatus string) goDependencySnapshot {
	declarations := append([]goDependencyDeclaration(nil), b.declarations...)
	sort.SliceStable(declarations, func(left, right int) bool {
		leftKey := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s", declarations[left].Kind, declarations[left].Owner, declarations[left].Module, declarations[left].Version, declarations[left].Replacement, declarations[left].Checksum)
		rightKey := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s", declarations[right].Kind, declarations[right].Owner, declarations[right].Module, declarations[right].Version, declarations[right].Replacement, declarations[right].Checksum)
		return leftKey < rightKey
	})
	packageKeys := make([]string, 0, len(b.packages))
	for key := range b.packages {
		packageKeys = append(packageKeys, key)
	}
	sort.Strings(packageKeys)
	packages := make([]goDependencySnapshotPackage, 0, len(packageKeys))
	modules := map[string]bool{}
	fileCount := 0
	for _, key := range packageKeys {
		entry := b.packages[key]
		packages = append(packages, entry)
		modules[entry.Module+"\x00"+entry.Replacement+"\x00"+entry.Source] = true
		fileCount += len(entry.Files)
	}
	reasons := make([]string, 0, len(b.reasons)+1)
	for reason := range b.reasons {
		reasons = append(reasons, reason)
	}
	status := "not-applicable"
	if b.hasDependency {
		switch loadStatus {
		case "loaded":
			status = "complete"
		case "partial":
			status = "partial"
			reasons = append(reasons, "typed-load-partial")
		default:
			status = "unavailable"
			reasons = append(reasons, "typed-load-fallback")
		}
		if len(b.reasons) > 0 && status == "complete" {
			status = "partial"
		}
	}
	sort.Strings(reasons)
	reasons = deduplicateSortedStrings(reasons)
	payload := map[string]any{
		"schema": goDependencySnapshotSchema, "status": status,
		"declarations": declarations, "packages": packages, "reasons": reasons,
	}
	return goDependencySnapshot{
		Status: status, Fingerprint: stableIDFromValue("go_dependency_snapshot", payload),
		ModuleCount: len(modules), PackageCount: len(packages), FileCount: fileCount, Reasons: reasons,
	}
}
