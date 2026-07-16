package worker

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type sourceFile struct {
	AbsPath       string
	RelPath       string
	Dir           string
	Module        *Module
	ImportPath    string
	PackageName   string
	IsTest        bool
	Generated     bool
	Condition     Condition
	ConditionText string
	AST           *ast.File
	FileSet       *token.FileSet
	Source        []byte
	ParseErr      error
	FileNodeID    string
}

type packageGroup struct {
	Dir         string
	ImportPath  string
	Module      *Module
	Files       []*sourceFile
	PackageNode Node
	BaseName    string
	Variants    map[string]Node
}

// localModuleResolution captures only the module relationships that the Go
// command would make local for a source module. Merely sharing a repository
// root is not sufficient: sibling modules require an active go.work use entry
// or an effective local replace directive.
type localModuleResolution struct {
	workspaceMembers  map[string]bool
	modulesByDir      map[string]Module
	modulesByPath     map[string][]Module
	replacementTarget map[string]map[string]string
}

func buildLocalModuleResolution(root string, modules []Module, work WorkFile) localModuleResolution {
	resolution := localModuleResolution{
		workspaceMembers:  goWorkMemberDirectories(root, work),
		modulesByDir:      make(map[string]Module, len(modules)),
		modulesByPath:     map[string][]Module{},
		replacementTarget: map[string]map[string]string{},
	}
	for _, module := range modules {
		resolution.modulesByDir[module.Dir] = module
		resolution.modulesByPath[module.Path] = append(resolution.modulesByPath[module.Path], module)
	}
	for modulePath := range resolution.modulesByPath {
		sort.Slice(resolution.modulesByPath[modulePath], func(i, j int) bool {
			return resolution.modulesByPath[modulePath][i].Dir < resolution.modulesByPath[modulePath][j].Dir
		})
	}

	workReplacements := map[string]Replacement{}
	for _, replacement := range work.Replacements {
		workReplacements[replacement.OldPath+"@"+replacement.OldVersion] = replacement
		if replacement.OldVersion == "" {
			workReplacements[replacement.OldPath+"@"] = replacement
		}
	}
	for _, module := range modules {
		moduleReplacements := map[string]Replacement{}
		for _, replacement := range module.Replacements {
			moduleReplacements[replacement.OldPath+"@"+replacement.OldVersion] = replacement
			if replacement.OldVersion == "" {
				moduleReplacements[replacement.OldPath+"@"] = replacement
			}
		}
		for _, requirement := range module.Requirements {
			replacement := Replacement{}
			hasReplacement := false
			fromWork := false
			if resolution.workspaceMembers[module.Dir] {
				replacement, hasReplacement = findReplacement(workReplacements, requirement)
				fromWork = hasReplacement
			}
			if !hasReplacement {
				replacement, hasReplacement = findReplacement(moduleReplacements, requirement)
			}
			if !hasReplacement {
				continue
			}
			baseModule := module
			if fromWork {
				baseModule.Dir = filepath.Dir(work.Path)
			}
			localDir, local, _ := resolveLocalReplacement(root, baseModule, replacement)
			if !local {
				continue
			}
			if _, discovered := resolution.modulesByDir[localDir]; !discovered {
				continue
			}
			byPath := resolution.replacementTarget[module.Dir]
			if byPath == nil {
				byPath = map[string]string{}
				resolution.replacementTarget[module.Dir] = byPath
			}
			byPath[requirement.Path] = localDir
		}
	}
	return resolution
}

func goWorkMemberDirectories(root string, work WorkFile) map[string]bool {
	members := map[string]bool{}
	if work.Path == "" {
		return members
	}
	workDir := filepath.Dir(work.Path)
	for _, use := range work.Uses {
		member := use
		if !filepath.IsAbs(member) {
			member = filepath.Join(workDir, filepath.FromSlash(member))
		}
		member = filepath.Clean(member)
		if evaluated, err := filepath.EvalSymlinks(member); err == nil {
			member = filepath.Clean(evaluated)
		}
		if isWithinRoot(root, member) {
			members[member] = true
		}
	}
	return members
}

func (resolution localModuleResolution) directlyVisible(sourceDir, targetDir string) bool {
	if sourceDir == targetDir {
		return true
	}
	return resolution.workspaceMembers[sourceDir] && resolution.workspaceMembers[targetDir]
}

func (resolution localModuleResolution) replacementImport(sourceDir, importPath string) (string, string, bool) {
	byPath := resolution.replacementTarget[sourceDir]
	oldPath := ""
	targetDir := ""
	for candidate, candidateTarget := range byPath {
		if importPath != candidate && !strings.HasPrefix(importPath, candidate+"/") {
			continue
		}
		if len(candidate) > len(oldPath) {
			oldPath = candidate
			targetDir = candidateTarget
		}
	}
	if oldPath == "" {
		return "", "", false
	}
	targetModule, ok := resolution.modulesByDir[targetDir]
	if !ok {
		return "", "", false
	}
	rewritten := strings.TrimSuffix(targetModule.Path, "/") + strings.TrimPrefix(importPath, oldPath)
	return targetDir, rewritten, true
}

func (resolution localModuleResolution) requirementTargets(source Module, requirement Requirement) []Module {
	if targetDir := resolution.replacementTarget[source.Dir][requirement.Path]; targetDir != "" {
		if target, ok := resolution.modulesByDir[targetDir]; ok {
			return []Module{target}
		}
	}
	var targets []Module
	for _, target := range resolution.modulesByPath[requirement.Path] {
		if resolution.directlyVisible(source.Dir, target.Dir) {
			targets = append(targets, target)
		}
	}
	return targets
}

type scannerState struct {
	root              string
	workspaceIdentity string
	profile           Profile
	goPackages        goPackagesInventory
	moduleResolution  localModuleResolution
	nodes             map[string]Node
	edges             map[string]Edge
	sites             map[string]Site
	diagnostics       []Diagnostic
	files             []FileCompletion
	unsupported       int
	unknownNodeID     string
	workspaceNodeID   string
}

func (s *scannerState) scopedID(kind string, parts ...string) string {
	return profileScopedID(kind, s.workspaceIdentity, s.profile.ID, parts...)
}

func Scan(root string) (Result, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Result{}, fmt.Errorf("normalize root: %w", err)
	}
	absRoot = filepath.Clean(absRoot)
	evaluated, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return Result{}, fmt.Errorf("resolve root: %w", err)
	}
	absRoot = filepath.Clean(evaluated)
	info, err := os.Lstat(absRoot)
	if err != nil {
		return Result{}, fmt.Errorf("read root: %w", err)
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("scan root is not a directory: %s", absRoot)
	}

	manifestPaths, skippedMetadata, initialDiagnostics, err := findManifests(absRoot)
	if err != nil {
		return Result{}, fmt.Errorf("discover go.mod files: %w", err)
	}
	var modules []Module
	for _, manifest := range manifestPaths {
		module, diagnostics := parseGoMod(manifest, absRoot)
		modules = append(modules, module)
		initialDiagnostics = append(initialDiagnostics, diagnostics...)
	}
	if runtime.Version() != "go1.26.1" {
		initialDiagnostics = append(initialDiagnostics, Diagnostic{
			Code: "go_toolchain_best_effort", Severity: "warning", Recoverable: true,
			Message: fmt.Sprintf("worker toolchain %s is outside the verified go1.26.1 baseline; analysis continues on a best-effort basis", runtime.Version()),
		})
	}
	for _, module := range modules {
		if module.GoVersion != "" && module.GoVersion != "1.26.1" {
			initialDiagnostics = append(initialDiagnostics, Diagnostic{
				Code: "go_module_version_best_effort", Severity: "info", Recoverable: true,
				Path:    relativePath(absRoot, module.ManifestPath),
				Message: fmt.Sprintf("module declares Go %s rather than the verified 1.26.1 baseline; analysis continues on a best-effort basis", module.GoVersion),
			})
		}
	}
	if len(modules) == 0 {
		modules = append(modules, Module{
			Dir: absRoot, RelativeDir: ".", Path: "local.invalid/root", ManifestPath: "",
		})
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].RelativeDir < modules[j].RelativeDir })

	work := WorkFile{}
	workPath := filepath.Join(absRoot, "go.work")
	if _, lstatErr := os.Lstat(workPath); lstatErr == nil {
		if _, resolveErr := resolveRegularFileWithinRoot(absRoot, workPath); resolveErr != nil {
			ledgerPath := skippedMetadataPath("go.work")
			reason := fmt.Sprintf("go.work could not be inventoried: %v", resolveErr)
			skippedMetadata = append(skippedMetadata, FileCompletion{
				Path: ledgerPath, DiscoveredSites: 1, SkippedSites: 1, Skipped: true, Reason: reason,
			})
			initialDiagnostics = append(initialDiagnostics, Diagnostic{
				Code: "path_confinement", Severity: "warning", Recoverable: true, Path: ledgerPath,
				Message: reason,
			})
		} else {
			var diagnostics []Diagnostic
			work, diagnostics = parseGoWork(workPath, absRoot)
			initialDiagnostics = append(initialDiagnostics, diagnostics...)
			for _, use := range work.Uses {
				usePath := use
				if !filepath.IsAbs(usePath) {
					usePath = filepath.Join(absRoot, filepath.FromSlash(usePath))
				}
				usePath = filepath.Clean(usePath)
				if evaluated, evalErr := filepath.EvalSymlinks(usePath); evalErr == nil {
					usePath = filepath.Clean(evaluated)
				}
				if !isWithinRoot(absRoot, usePath) {
					initialDiagnostics = append(initialDiagnostics, Diagnostic{
						Code: "path_confinement", Severity: "warning", Recoverable: true,
						Message: fmt.Sprintf("go.work use path %q is outside the scan root and was not traversed", use), Path: "go.work",
					})
				}
			}
		}
	} else if !os.IsNotExist(lstatErr) {
		reason := fmt.Sprintf("go.work could not be inventoried: %v", lstatErr)
		skippedMetadata = append(skippedMetadata, FileCompletion{
			Path: "go.work", DiscoveredSites: 1, SkippedSites: 1, Skipped: true, Reason: reason,
		})
		initialDiagnostics = append(initialDiagnostics, Diagnostic{
			Code: "go_work_read", Severity: "warning", Recoverable: true, Path: "go.work", Message: reason,
		})
	}

	identityParts := make([]string, 0, len(modules))
	for _, module := range modules {
		identityParts = append(identityParts, module.Path+"@"+module.RelativeDir)
	}
	workspaceIdentity := strings.Join(identityParts, "|")
	configuredTags := configuredGoTags()
	goPackages := loadGoPackagesInventory(absRoot, modules, work, configuredTags)
	initialDiagnostics = append(initialDiagnostics, goPackages.Diagnostics...)
	// The constrained typed-package pass always disables cgo. GOOS/GOARCH and this
	// effective cgo state are profile axes even when no custom build tags were
	// requested; otherwise host scans on different platforms would share IDs.
	const cgoEnabled = "0"
	profileID := goProfileID(runtime.GOOS, runtime.GOARCH, cgoEnabled, configuredTags)
	profileProperties := map[string]string{
		"variants": "normal,internal_test,external_test", "safe_scan": "true", "configured_tags": strings.Join(configuredTags, ","),
	}
	for key, value := range inventoryProperties(goPackages) {
		profileProperties[key] = value
	}
	profile := Profile{
		ID: profileID, Language: "go", Toolchain: runtime.Version(), Command: "scan", Target: runtime.GOOS + "-" + runtime.GOARCH,
		Features:    configuredTags,
		Environment: map[string]string{"GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "CGO_ENABLED": cgoEnabled, "GO_TAGS": strings.Join(configuredTags, ",")},
		Properties:  profileProperties,
	}
	state := &scannerState{
		root: absRoot, workspaceIdentity: workspaceIdentity, profile: profile, goPackages: goPackages,
		moduleResolution: buildLocalModuleResolution(absRoot, modules, work),
		nodes:            map[string]Node{}, edges: map[string]Edge{}, sites: map[string]Site{}, diagnostics: initialDiagnostics,
		files: skippedMetadata,
	}
	state.workspaceNodeID = stableID("workspace", workspaceIdentity, "root")
	if err := addNode(state.nodes, Node{
		ID: state.workspaceNodeID, Kind: "workspace", Locator: "go-workspace:" + workspaceIdentity,
		DisplayName: "Go workspace", Properties: map[string]any{"root": ".", "go_work": work.Path != ""},
	}); err != nil {
		return Result{}, err
	}

	moduleNodes, err := state.addModules(modules, work)
	if err != nil {
		return Result{}, err
	}
	sources, err := state.discoverAndParseFiles(modules)
	if err != nil {
		return Result{}, err
	}
	discoveredFiles := len(sources) + len(state.files) + len(manifestPaths)
	if work.Path != "" {
		discoveredFiles++
	}
	groups, err := state.addPackagesAndFiles(sources, moduleNodes)
	if err != nil {
		return Result{}, err
	}
	state.addModuleRequirements(modules, work, moduleNodes)
	state.addManifestCompletions(modules, work)
	for _, source := range sources {
		state.extractFileDependencies(source, groups)
	}

	result := state.result(discoveredFiles)
	return result, nil
}

func (s *scannerState) addManifestCompletions(modules []Module, work WorkFile) {
	for _, module := range modules {
		if module.ManifestPath == "" {
			continue
		}
		rel := relativePath(s.root, module.ManifestPath)
		completion := FileCompletion{
			Path: rel, DiscoveredSites: len(module.Requirements), EmittedSites: len(module.Requirements),
		}
		if s.hasReadDiagnostic("go_mod_read", rel) {
			// A read failure is one incomplete inventory item regardless of any
			// parser diagnostics recovered before the failure. Keep already emitted
			// requirements in the ledger and do not count them twice.
			completion.DiscoveredSites++
			completion.SkippedSites = 1
			completion.Skipped = true
			completion.Reason = "go.mod could not be read"
		} else if module.ParseIssues > 0 {
			completion.DiscoveredSites += module.ParseIssues
			completion.SkippedSites = module.ParseIssues
			completion.Skipped = true
			completion.Reason = "go.mod syntax was only partially parsed"
			s.unsupported += module.ParseIssues
		}
		s.files = append(s.files, completion)
	}
	if work.Path != "" {
		rel := relativePath(s.root, work.Path)
		completion := FileCompletion{Path: rel}
		if s.hasReadDiagnostic("go_work_read", rel) {
			completion.DiscoveredSites = 1
			completion.SkippedSites = 1
			completion.Skipped = true
			completion.Reason = "go.work could not be read"
		} else if work.ParseIssues > 0 {
			completion.DiscoveredSites = work.ParseIssues
			completion.SkippedSites = work.ParseIssues
			completion.Skipped = true
			completion.Reason = "go.work syntax was only partially parsed"
			s.unsupported += work.ParseIssues
		}
		s.files = append(s.files, completion)
	}
}

func (s *scannerState) hasReadDiagnostic(code, path string) bool {
	for _, diagnostic := range s.diagnostics {
		if diagnostic.Code == code && diagnostic.Path == path {
			return true
		}
	}
	return false
}

func (s *scannerState) addModules(modules []Module, work WorkFile) (map[string]Node, error) {
	moduleNodes := make(map[string]Node, len(modules))
	for i := range modules {
		module := &modules[i]
		workspaceMember := work.Path == "" || s.moduleResolution.workspaceMembers[module.Dir]
		locator := "gomod:" + module.Path
		if module.RelativeDir != "." {
			locator += "#" + module.RelativeDir
		}
		node := Node{
			ID: s.scopedID("package_instance", module.Path, module.RelativeDir), Kind: "package_instance",
			Locator: locator, DisplayName: module.Path,
			Properties: map[string]any{
				"ecosystem": "go", "module_path": module.Path, "relative_dir": module.RelativeDir,
				"go_version": module.GoVersion, "toolchain": module.Toolchain, "workspace_member": workspaceMember,
			},
		}
		if err := addNode(s.nodes, node); err != nil {
			return nil, err
		}
		moduleNodes[module.Dir] = node
		manifest := module.ManifestPath
		if manifest == "" {
			manifest = s.root
		}
		s.addStructuralEdge(s.workspaceNodeID, node.ID, "contains", AlwaysCondition(), sourceEvidence(relativePath(s.root, manifest), 1, 1, 1, 1, "workspace module"))
	}
	return moduleNodes, nil
}

func (s *scannerState) discoverAndParseFiles(modules []Module) ([]*sourceFile, error) {
	var paths []string
	err := filepath.WalkDir(s.root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && path != s.root && shouldSkipDirectory(entry.Name()) {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			if strings.HasSuffix(entry.Name(), ".go") && !strings.HasPrefix(entry.Name(), ".") && !strings.HasPrefix(entry.Name(), "_") {
				originalPath := relativePath(s.root, path)
				ledgerPath := originalPath
				code := "go_source_symlink_skipped"
				reason := fmt.Sprintf("Go source symlink %s was not followed in safe mode", originalPath)
				if resolved, resolveErr := filepath.EvalSymlinks(path); resolveErr != nil || !isWithinRoot(s.root, resolved) {
					ledgerPath = skippedMetadataPath(originalPath)
					code = "path_confinement"
					reason = fmt.Sprintf("Go source symlink %s could not be confined to the scan root", originalPath)
					if resolveErr != nil {
						reason += fmt.Sprintf(": %v", resolveErr)
					}
				}
				s.diagnostics = append(s.diagnostics, Diagnostic{
					Code: code, Severity: "warning", Message: reason, Path: ledgerPath, Recoverable: true,
				})
				s.files = append(s.files, FileCompletion{
					Path: ledgerPath, DiscoveredSites: 1, SkippedSites: 1, Skipped: true, Reason: reason,
				})
			}
			return nil
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") && !strings.HasPrefix(entry.Name(), ".") && !strings.HasPrefix(entry.Name(), "_") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover Go files: %w", err)
	}
	sort.Strings(paths)
	sources := make([]*sourceFile, 0, len(paths))
	for _, path := range paths {
		sourceBytes, readErr := readRegularFileWithinRoot(s.root, path)
		rel := relativePath(s.root, path)
		if readErr != nil {
			ledgerPath := rel
			code := "go_file_read"
			if errors.Is(readErr, errPathConfinement) {
				ledgerPath = skippedMetadataPath(rel)
				code = "path_confinement"
			}
			reason := fmt.Sprintf("Go source %s could not be read: %v", rel, readErr)
			s.diagnostics = append(s.diagnostics, Diagnostic{Code: code, Severity: "error", Message: reason, Path: ledgerPath, Recoverable: true})
			s.files = append(s.files, FileCompletion{
				Path: ledgerPath, DiscoveredSites: 1, SkippedSites: 1, Skipped: true,
				Reason: reason,
			})
			continue
		}
		module := moduleForPath(modules, path)
		if module == nil {
			module = &modules[0]
		}
		fset := token.NewFileSet()
		parsed, parseErr := parser.ParseFile(fset, path, sourceBytes, parser.ParseComments|parser.AllErrors)
		condition, conditionText, conditionErr := parseBuildCondition(sourceBytes)
		if conditionErr != nil {
			s.unsupported++
			s.diagnostics = append(s.diagnostics, Diagnostic{Code: "go_build_constraint", Severity: "warning", Message: conditionErr.Error(), Path: rel, Recoverable: true})
		}
		packageName := "unknown"
		if parsed != nil && parsed.Name != nil {
			packageName = parsed.Name.Name
		}
		if filenameCondition, filenameText, ok := buildConditionFromFilename(filepath.Base(path)); ok {
			condition = combineConditions(condition, filenameCondition)
			conditionText = joinConditionText(conditionText, filenameText)
		}
		if parsed != nil && hasCgoImport(parsed) {
			condition = combineConditions(condition, buildTagCondition("cgo"))
			conditionText = joinConditionText(conditionText, "cgo")
		}
		source := &sourceFile{
			AbsPath: path, RelPath: rel, Dir: filepath.Dir(path), Module: module,
			PackageName: packageName, IsTest: strings.HasSuffix(path, "_test.go"), Generated: isGenerated(sourceBytes),
			Condition: condition, ConditionText: conditionText, AST: parsed, FileSet: fset, Source: sourceBytes, ParseErr: parseErr,
		}
		source.ImportPath = packageImportPath(s.root, *module, source.Dir)
		source.FileNodeID = s.scopedID("file", module.Path, source.RelPath)
		if parseErr != nil {
			s.unsupported++
			evidence := sourceEvidence(rel, 1, 1, 1, 1, "parse error")
			s.diagnostics = append(s.diagnostics, Diagnostic{Code: "go_parse_error", Severity: "warning", Message: parseErr.Error(), Path: rel, Evidence: evidence, Recoverable: true})
		}
		sources = append(sources, source)
	}
	return sources, nil
}

func (s *scannerState) addPackagesAndFiles(sources []*sourceFile, moduleNodes map[string]Node) (map[string][]*packageGroup, error) {
	groupsByDir := map[string]*packageGroup{}
	for _, source := range sources {
		group := groupsByDir[source.Dir]
		if group == nil {
			group = &packageGroup{Dir: source.Dir, ImportPath: source.ImportPath, Module: source.Module, Variants: map[string]Node{}}
			groupsByDir[source.Dir] = group
		}
		group.Files = append(group.Files, source)
		if !source.IsTest && group.BaseName == "" {
			group.BaseName = source.PackageName
		}
	}

	groupsByImport := map[string][]*packageGroup{}
	dirs := make([]string, 0, len(groupsByDir))
	for dir := range groupsByDir {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		group := groupsByDir[dir]
		if group.BaseName == "" && len(group.Files) > 0 {
			group.BaseName = strings.TrimSuffix(group.Files[0].PackageName, "_test")
		}
		packageNode := Node{
			ID: s.scopedID("module", group.Module.Path, group.ImportPath), Kind: "module",
			Locator: "go-package:" + group.ImportPath, DisplayName: group.ImportPath,
			Properties: map[string]any{
				"language": "go", "module_path": group.Module.Path, "package_name": group.BaseName,
				"relative_dir": relativePath(s.root, dir), "vendor": isVendorDirectory(s.root, dir),
			},
		}
		if err := addNode(s.nodes, packageNode); err != nil {
			return nil, err
		}
		group.PackageNode = packageNode
		groupsByImport[group.ImportPath] = append(groupsByImport[group.ImportPath], group)
		moduleNode := moduleNodes[group.Module.Dir]
		packageEvidence := sourceEvidence(group.Files[0].RelPath, 1, 1, 1, 1, "package declaration")
		s.addStructuralEdge(moduleNode.ID, packageNode.ID, "contains", AlwaysCondition(), packageEvidence)

		variants := variantsForGroup(group)
		for _, variant := range variants {
			unit := Node{
				ID: s.scopedID("build_unit", group.Module.Path, group.ImportPath, variant), Kind: "build_unit",
				Locator: "go-unit:" + group.ImportPath + "#" + variant, DisplayName: group.ImportPath + " (" + variant + ")",
				Properties: map[string]any{"language": "go", "package_path": group.ImportPath, "variant": variant, "profile_id": s.profile.ID},
			}
			if err := addNode(s.nodes, unit); err != nil {
				return nil, err
			}
			group.Variants[variant] = unit
			s.addStructuralEdge(packageNode.ID, unit.ID, "contains", AlwaysCondition(), packageEvidence)
		}

		for _, source := range group.Files {
			fileNode := Node{
				ID: source.FileNodeID, Kind: "file", Locator: "file:" + source.RelPath, DisplayName: source.RelPath,
				Properties: map[string]any{
					"language": "go", "package_path": group.ImportPath, "package_name": source.PackageName,
					"generated": source.Generated, "test": source.IsTest, "build_constraint": source.ConditionText,
				},
			}
			if err := addNode(s.nodes, fileNode); err != nil {
				return nil, err
			}
			for _, variant := range variantsForFile(group, source) {
				if unit, ok := group.Variants[variant]; ok {
					s.addStructuralEdge(unit.ID, fileNode.ID, "contains", source.Condition, sourceEvidence(source.RelPath, 1, 1, 1, 1, ""))
				}
			}
		}
	}
	return groupsByImport, nil
}

func (s *scannerState) addModuleRequirements(modules []Module, work WorkFile, moduleNodes map[string]Node) {
	workReplacements := map[string]Replacement{}
	for _, replacement := range work.Replacements {
		workReplacements[replacement.OldPath+"@"+replacement.OldVersion] = replacement
		if replacement.OldVersion == "" {
			workReplacements[replacement.OldPath+"@"] = replacement
		}
	}
	for _, module := range modules {
		sourceNode := moduleNodes[module.Dir]
		moduleReplacements := map[string]Replacement{}
		for _, replacement := range module.Replacements {
			moduleReplacements[replacement.OldPath+"@"+replacement.OldVersion] = replacement
			if replacement.OldVersion == "" {
				moduleReplacements[replacement.OldPath+"@"] = replacement
			}
		}
		for _, requirement := range module.Requirements {
			replacement := Replacement{}
			hasReplacement := false
			workReplacement := false
			if s.moduleResolution.workspaceMembers[module.Dir] {
				replacement, hasReplacement = findReplacement(workReplacements, requirement)
				workReplacement = hasReplacement
			}
			if !hasReplacement {
				replacement, hasReplacement = findReplacement(moduleReplacements, requirement)
			}
			status := "external"
			var targetIDs []string
			targetModulePath := requirement.Path
			targetVersion := requirement.Version
			targetDisplay := targetModulePath
			targetProperties := map[string]any{"ecosystem": "go", "module_path": targetModulePath, "version": targetVersion, "external": true}
			if !hasReplacement {
				for _, local := range s.moduleResolution.requirementTargets(module, requirement) {
					if target, ok := moduleNodes[local.Dir]; ok {
						targetIDs = append(targetIDs, target.ID)
					}
				}
			}
			if hasReplacement {
				targetProperties["replace_path"] = replacement.NewPath
				targetProperties["replace_version"] = replacement.NewVersion
				targetProperties["requested_module_path"] = requirement.Path
				targetProperties["requested_version"] = requirement.Version
				if replacement.NewVersion != "" {
					targetModulePath = replacement.NewPath
					targetVersion = replacement.NewVersion
					targetDisplay = targetModulePath
					targetProperties["module_path"] = targetModulePath
					targetProperties["version"] = targetVersion
				}
				baseModule := module
				if workReplacement {
					baseModule.Dir = filepath.Dir(work.Path)
				}
				if localDir, local, reason := resolveLocalReplacement(s.root, baseModule, replacement); local {
					if targetModule, ok := s.moduleResolution.modulesByDir[localDir]; ok {
						targetIDs = append(targetIDs, moduleNodes[targetModule.Dir].ID)
					} else {
						s.diagnostics = append(s.diagnostics, Diagnostic{
							Code: "go_replace_target", Severity: "warning", Recoverable: true, Path: relativePath(s.root, module.ManifestPath),
							Message: fmt.Sprintf("local replacement %q has no discovered go.mod", replacement.NewPath),
						})
					}
				} else if reason != "" {
					s.diagnostics = append(s.diagnostics, Diagnostic{
						Code: "path_confinement", Severity: "warning", Recoverable: true, Path: relativePath(s.root, module.ManifestPath), Message: reason,
					})
				}
			}
			sort.Strings(targetIDs)
			targetIDs = deduplicateSortedStrings(targetIDs)
			if len(targetIDs) == 0 {
				locator := "gomod:" + targetModulePath + "@" + targetVersion
				targetProperties["target_kind"] = "package_instance"
				targetID := s.scopedID("external_system", requirement.Path, requirement.Version, replacement.NewPath, replacement.NewVersion)
				targetNode := Node{ID: targetID, Kind: "external_system", Locator: locator, DisplayName: targetDisplay, Properties: targetProperties}
				if err := addNode(s.nodes, targetNode); err != nil {
					s.diagnostics = append(s.diagnostics, Diagnostic{Code: "identity_conflict", Severity: "error", Message: err.Error(), Recoverable: false})
				}
				targetIDs = []string{targetID}
			} else if len(targetIDs) == 1 {
				status = "resolved"
			} else {
				status = "candidates"
			}
			relManifest := relativePath(s.root, module.ManifestPath)
			evidence := sourceEvidence(relManifest, requirement.Line, 1, requirement.Line, 1, requirement.Path+" "+requirement.Version)
			siteID := s.scopedID("site", relManifest, strconv.Itoa(requirement.Line), "module_requirement", requirement.Path)
			site := Site{
				ID: siteID, Source: sourceNode.ID, Kind: "module_requirement", Specifier: requirement.Path,
				ResolutionStatus: status, TargetIDs: targetIDs, ProfileID: s.profile.ID,
				Condition: AlwaysCondition(), Precision: "exact", Evidence: evidence,
			}
			s.addSiteWithEdges(site, "depends_on")
		}
	}
}

func (s *scannerState) extractFileDependencies(source *sourceFile, groups map[string][]*packageGroup) {
	discoveredBefore := len(s.sites)
	if source.AST == nil {
		s.files = append(s.files, FileCompletion{
			Path: source.RelPath, DiscoveredSites: 1, SkippedSites: 1, Skipped: true,
			Reason: "Go syntax could not be parsed",
		})
		return
	}
	for _, spec := range source.AST.Imports {
		value, err := strconv.Unquote(spec.Path.Value)
		position := source.FileSet.Position(spec.Pos())
		end := source.FileSet.Position(spec.End())
		evidence := sourceEvidence(source.RelPath, position.Line, position.Column, end.Line, end.Column, spec.Path.Value)
		if err != nil || value == "" {
			s.addUnresolvedSite(source, "import", spec.Path.Value, "invalid import path literal", evidence)
			continue
		}
		if value == "C" {
			s.addExternalSite(source, "cgo_import", value, "links", "native_library", "cgo:C", "C toolchain", evidence, map[string]any{"language": "c", "cgo": true})
			continue
		}
		if strings.HasPrefix(value, ".") || strings.Contains(value, "\\") {
			s.addUnresolvedSite(source, importSiteKind(spec), value, "relative or non-canonical imports are not resolved in module mode", evidence)
			continue
		}
		if targets := resolveLocalGroups(source, value, groups, s.moduleResolution); len(targets) > 0 {
			siteID := s.scopedID("site", source.RelPath, strconv.Itoa(position.Offset), "import", value)
			targetIDs := make([]string, 0, len(targets))
			for _, target := range targets {
				targetIDs = append(targetIDs, target.PackageNode.ID)
			}
			status := "resolved"
			if len(targetIDs) > 1 {
				status = "candidates"
			}
			site := Site{
				ID: siteID, Source: source.FileNodeID, Kind: importSiteKind(spec), Specifier: value,
				ResolutionStatus: status, TargetIDs: targetIDs, ProfileID: s.profile.ID,
				Condition: source.Condition, Precision: "exact", Evidence: evidence,
			}
			s.addSiteWithEdges(site, importEdgeKind(spec))
		} else {
			properties := map[string]any{"ecosystem": "go", "import_path": value, "standard_library": looksLikeStandardLibrary(value)}
			s.addExternalSite(source, importSiteKind(spec), value, importEdgeKind(spec), "external_system", "go-import:"+value, value, evidence, properties)
		}
	}

	s.extractEmbedDirectives(source)
	s.extractGenerateDirectives(source)
	if hasCgoImport(source.AST) {
		s.extractCgoDirectives(source)
	}
	emitted := len(s.sites) - discoveredBefore
	completion := FileCompletion{Path: source.RelPath, DiscoveredSites: emitted, EmittedSites: emitted}
	if source.ParseErr != nil {
		// The Go parser may return a useful partial AST. Preserve every site that
		// was recovered, but reserve one skipped ledger entry for syntax that could
		// not be inventoried. This keeps discovered=emitted+skipped explicit.
		completion.DiscoveredSites++
		completion.SkippedSites = 1
		completion.Skipped = true
		completion.Reason = "Go syntax was only partially parsed"
	}
	s.files = append(s.files, completion)
}

func (s *scannerState) addUnresolvedSite(source *sourceFile, kind, specifier, reason string, evidence []Evidence) {
	unknownID := s.ensureUnknownNode()
	line := 0
	column := 0
	if len(evidence) > 0 {
		line = evidence[0].StartLine
		column = evidence[0].StartColumn
	}
	site := Site{
		ID:     s.scopedID("site", source.RelPath, strconv.Itoa(line), strconv.Itoa(column), kind, specifier),
		Source: source.FileNodeID, Kind: kind, Specifier: specifier, ResolutionStatus: "unresolved", TargetIDs: []string{unknownID},
		ProfileID: s.profile.ID, Condition: source.Condition, Precision: "heuristic", Evidence: evidence, Reason: reason,
	}
	s.addSiteWithEdges(site, edgeKindForSite(kind))
}

func (s *scannerState) addExternalSite(source *sourceFile, kind, specifier, edgeKind, nodeKind, locator, display string, evidence []Evidence, properties map[string]any) {
	s.addExternalSiteWithCondition(source, kind, specifier, edgeKind, nodeKind, locator, display, source.Condition, evidence, properties)
}

func (s *scannerState) addExternalSiteWithCondition(source *sourceFile, kind, specifier, edgeKind, nodeKind, locator, display string, condition Condition, evidence []Evidence, properties map[string]any) {
	targetID := s.scopedID("external_system", locator)
	properties["external"] = true
	properties["target_kind"] = nodeKind
	if err := addNode(s.nodes, Node{ID: targetID, Kind: "external_system", Locator: locator, DisplayName: display, Properties: properties}); err != nil {
		s.diagnostics = append(s.diagnostics, Diagnostic{Code: "identity_conflict", Severity: "error", Message: err.Error(), Recoverable: false})
	}
	line := 0
	column := 0
	if len(evidence) > 0 {
		line = evidence[0].StartLine
		column = evidence[0].StartColumn
	}
	site := Site{
		ID:     s.scopedID("site", source.RelPath, strconv.Itoa(line), strconv.Itoa(column), kind, specifier),
		Source: source.FileNodeID, Kind: kind, Specifier: specifier, ResolutionStatus: "external", TargetIDs: []string{targetID},
		ProfileID: s.profile.ID, Condition: canonicalCondition(condition), Precision: "exact", Evidence: evidence,
	}
	s.addSiteWithEdges(site, edgeKind)
}

func (s *scannerState) addSiteWithEdges(site Site, edgeKind string) {
	if old, ok := s.sites[site.ID]; ok {
		// Multiple identical directives may produce the same canonical site. Preserve
		// each source location through the ID, so reaching this branch means a true
		// duplicate and is safe to coalesce only if the payload is identical.
		oldJSON := fmt.Sprintf("%#v", old)
		newJSON := fmt.Sprintf("%#v", site)
		if oldJSON != newJSON {
			s.diagnostics = append(s.diagnostics, Diagnostic{Code: "identity_conflict", Severity: "error", Message: "conflicting dependency site " + site.ID, Recoverable: false})
		}
		return
	}
	s.sites[site.ID] = site
	for _, target := range site.TargetIDs {
		generated := false
		if sourceNode, ok := s.nodes[site.Source]; ok {
			generated, _ = sourceNode.Properties["generated"].(bool)
		}
		edge := Edge{
			Source: site.Source, Target: target, Kind: edgeKind, SiteID: site.ID,
			Phase: "source", Environment: "any", ResolutionStatus: site.ResolutionStatus, ProfileID: site.ProfileID,
			Condition: site.Condition, Precision: site.Precision, Generated: generated,
			Evidence: append([]Evidence(nil), site.Evidence...),
		}
		edge.ID = edgeID(s.workspaceIdentity, edge)
		s.edges[edge.ID] = edge
	}
}

func (s *scannerState) addStructuralEdge(source, target, kind string, condition Condition, evidence []Evidence) {
	if evidence == nil {
		evidence = []Evidence{}
	}
	generated := false
	if sourceNode, ok := s.nodes[source]; ok {
		generated, _ = sourceNode.Properties["generated"].(bool)
	}
	if targetNode, ok := s.nodes[target]; ok {
		if targetGenerated, ok := targetNode.Properties["generated"].(bool); ok {
			generated = generated || targetGenerated
		}
	}
	edge := Edge{
		Source: source, Target: target, Kind: kind, Phase: "source", Environment: "any",
		ResolutionStatus: "resolved", ProfileID: s.profile.ID, Condition: condition,
		Precision: "exact", Generated: generated, Evidence: evidence,
	}
	edge.ID = edgeID(s.workspaceIdentity, edge)
	s.edges[edge.ID] = edge
}

func (s *scannerState) ensureUnknownNode() string {
	if s.unknownNodeID != "" {
		return s.unknownNodeID
	}
	s.unknownNodeID = s.scopedID("unknown_target", "go")
	_ = addNode(s.nodes, Node{
		ID: s.unknownNodeID, Kind: "unknown_target", Locator: "unknown:go", DisplayName: "Unknown Go target",
		Properties: map[string]any{"language": "go"},
	})
	return s.unknownNodeID
}

func (s *scannerState) result(discoveredFiles int) Result {
	result := Result{Root: s.root, Profile: s.profile, Diagnostics: s.diagnostics, Files: s.files}
	for _, node := range s.nodes {
		result.Nodes = append(result.Nodes, node)
	}
	for _, site := range s.sites {
		result.Sites = append(result.Sites, site)
		switch site.ResolutionStatus {
		case "resolved":
			result.Coverage.Resolved++
		case "candidates":
			result.Coverage.Candidates++
		case "external":
			result.Coverage.External++
		case "unresolved":
			result.Coverage.Unresolved++
		}
	}
	for _, edge := range s.edges {
		result.Edges = append(result.Edges, edge)
	}
	result.Coverage.Profiles = 1
	result.Coverage.FilesDiscovered = discoveredFiles
	for _, file := range s.files {
		if file.Skipped {
			result.Coverage.FilesSkipped++
		} else {
			result.Coverage.FilesAnalyzed++
		}
	}
	result.Coverage.DependencySites = len(result.Sites)
	result.Coverage.UnsupportedSyntax = s.unsupported
	result.Coverage.ProjectCodeExecuted = false
	result.Coverage.Completeness = []string{}
	result.Coverage.Reasons = []string{}
	if result.Coverage.FilesSkipped == 0 && result.Coverage.UnsupportedSyntax == 0 {
		result.Coverage.Completeness = append(result.Coverage.Completeness, "syntax-complete")
	}
	if s.goPackages.Fallback {
		result.Coverage.Reasons = append(result.Coverage.Reasons, "go-packages-parser-fallback")
	}
	if result.Coverage.FilesSkipped > 0 {
		result.Coverage.Reasons = append(result.Coverage.Reasons, "files-skipped")
	}
	if result.Coverage.UnsupportedSyntax > 0 {
		result.Coverage.Reasons = append(result.Coverage.Reasons, "unsupported-syntax")
	}
	if result.Coverage.Unresolved > 0 {
		result.Coverage.Reasons = append(result.Coverage.Reasons, "unresolved-sites")
	}
	for index := range result.Diagnostics {
		if result.Diagnostics[index].ID == "" {
			diagnostic := &result.Diagnostics[index]
			diagnostic.ID = s.scopedID("diagnostic", diagnostic.Code, diagnostic.Path, diagnostic.Message)
		}
	}
	sortResult(&result)
	return result
}

func (s *scannerState) extractEmbedDirectives(source *sourceFile) {
	lines := bytes.Split(source.Source, []byte("\n"))
	for index, lineBytes := range lines {
		line := strings.TrimSpace(string(lineBytes))
		if !strings.HasPrefix(line, "//go:embed") {
			continue
		}
		args := strings.TrimSpace(strings.TrimPrefix(line, "//go:embed"))
		patterns, err := splitDirectiveArguments(args)
		lineNo := index + 1
		evidence := sourceEvidence(source.RelPath, lineNo, 1, lineNo, len(line)+1, line)
		if err != nil || len(patterns) == 0 {
			reason := "go:embed directive has no valid patterns"
			if err != nil {
				reason = err.Error()
			}
			s.addUnresolvedSite(source, "embed", args, reason, evidence)
			continue
		}
		for patternIndex, pattern := range patterns {
			matches, reason := s.resolveEmbedPattern(source, pattern)
			siteID := s.scopedID("site", source.RelPath, strconv.Itoa(lineNo), "embed", strconv.Itoa(patternIndex), pattern)
			if len(matches) == 0 {
				unknownID := s.ensureUnknownNode()
				s.addSiteWithEdges(Site{
					ID: siteID, Source: source.FileNodeID, Kind: "embed", Specifier: pattern, ResolutionStatus: "unresolved",
					TargetIDs: []string{unknownID}, ProfileID: s.profile.ID, Condition: source.Condition, Precision: "exact", Evidence: evidence, Reason: reason,
				}, "loads")
				continue
			}
			targets := make([]string, 0, len(matches))
			for _, match := range matches {
				rel := relativePath(s.root, match)
				targetID := s.scopedID("file", source.Module.Path, rel)
				info, _ := os.Stat(match)
				properties := map[string]any{"language": "asset", "embedded": true, "module_path": source.Module.Path}
				if info != nil {
					properties["size"] = info.Size()
				}
				if err := addNode(s.nodes, Node{ID: targetID, Kind: "file", Locator: "file:" + rel, DisplayName: rel, Properties: properties}); err != nil {
					s.diagnostics = append(s.diagnostics, Diagnostic{Code: "identity_conflict", Severity: "error", Message: err.Error(), Recoverable: false})
				}
				targets = append(targets, targetID)
			}
			status := "resolved"
			if len(targets) > 1 {
				status = "candidates"
			}
			s.addSiteWithEdges(Site{
				ID: siteID, Source: source.FileNodeID, Kind: "embed", Specifier: pattern, ResolutionStatus: status,
				TargetIDs: targets, ProfileID: s.profile.ID, Condition: source.Condition, Precision: "exact", Evidence: evidence,
			}, "loads")
		}
	}
}

func (s *scannerState) resolveEmbedPattern(source *sourceFile, pattern string) ([]string, string) {
	original := pattern
	includeHidden := false
	if strings.HasPrefix(pattern, "all:") {
		includeHidden = true
		pattern = strings.TrimPrefix(pattern, "all:")
	}
	if pattern == "" || filepath.IsAbs(pattern) || strings.Contains(pattern, "\\") {
		return nil, "invalid go:embed pattern"
	}
	clean := filepath.Clean(filepath.FromSlash(pattern))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, "go:embed pattern escapes the package directory"
	}
	absPattern := filepath.Join(source.Dir, clean)
	if !isWithinRoot(s.root, absPattern) {
		return nil, "go:embed pattern escapes the scan root"
	}
	matches, err := filepath.Glob(absPattern)
	if err != nil {
		return nil, "invalid go:embed pattern " + strconv.Quote(original)
	}
	resultSet := map[string]bool{}
	for _, match := range matches {
		evaluated, evalErr := filepath.EvalSymlinks(match)
		if evalErr != nil || !isWithinRoot(s.root, evaluated) {
			continue
		}
		info, err := os.Lstat(match)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if info.IsDir() {
			_ = filepath.WalkDir(match, func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return nil
				}
				if path != match && entry.IsDir() && !includeHidden && (strings.HasPrefix(entry.Name(), ".") || strings.HasPrefix(entry.Name(), "_")) {
					return filepath.SkipDir
				}
				if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
					return nil
				}
				if !includeHidden && (strings.HasPrefix(entry.Name(), ".") || strings.HasPrefix(entry.Name(), "_")) {
					return nil
				}
				evaluatedPath, evalErr := filepath.EvalSymlinks(path)
				if evalErr == nil && isWithinRoot(s.root, evaluatedPath) {
					resultSet[path] = true
				}
				return nil
			})
		} else if info.Mode().IsRegular() {
			base := filepath.Base(match)
			if includeHidden || (!strings.HasPrefix(base, ".") && !strings.HasPrefix(base, "_")) {
				resultSet[match] = true
			}
		}
	}
	results := make([]string, 0, len(resultSet))
	for match := range resultSet {
		results = append(results, match)
	}
	sort.Strings(results)
	if len(results) == 0 {
		return nil, "go:embed pattern matched no files"
	}
	return results, ""
}

func (s *scannerState) extractGenerateDirectives(source *sourceFile) {
	lines := bytes.Split(source.Source, []byte("\n"))
	for index, lineBytes := range lines {
		line := strings.TrimSpace(string(lineBytes))
		if !strings.HasPrefix(line, "//go:generate") {
			continue
		}
		s.diagnostics = append(s.diagnostics, Diagnostic{
			Code: "go_generate_not_executed", Severity: "info", Recoverable: true, Path: source.RelPath,
			Message:  "go:generate invocation was recorded but not executed",
			Evidence: sourceEvidence(source.RelPath, index+1, 1, index+1, len(line)+1, line),
		})
	}
}

func (s *scannerState) extractCgoDirectives(source *sourceFile) {
	for _, preamble := range cgoPreambleLines(source) {
		line := preamble.Text
		evidence := sourceEvidence(source.RelPath, preamble.Line, preamble.Column, preamble.Line, preamble.EndColumn, line)
		if directive, arguments, directiveCondition, ok := parseCgoDirective(line); ok {
			condition := combineConditions(source.Condition, directiveCondition)
			libraries := cgoLibraries(arguments)
			for _, library := range libraries {
				s.addExternalSiteWithCondition(
					source, "cgo_library", library, "links", "native_library", "native-library:"+library, library,
					condition, evidence, map[string]any{"directive": directive, "arguments": arguments, "link_flag": "-l" + library, "cgo": true},
				)
			}
			if len(libraries) == 0 {
				specifier := directive + ":" + arguments
				s.addExternalSiteWithCondition(
					source, "cgo_directive", specifier, "build_depends_on", "external_system",
					"cgo-directive:"+strings.ToLower(directive), directive, condition, evidence,
					map[string]any{"directive": directive, "arguments": arguments, "cgo": true},
				)
			}
			continue
		}
		if strings.HasPrefix(line, "#include") {
			header := strings.TrimSpace(strings.TrimPrefix(line, "#include"))
			if header != "" {
				s.addExternalSite(source, "cgo_header", header, "build_depends_on", "external_system", "c-header:"+header, header, evidence, map[string]any{"language": "c", "cgo": true})
			}
		}
	}
}

type cgoPreambleLine struct {
	Text      string
	Line      int
	Column    int
	EndColumn int
}

// cgoPreambleLines only reads comments attached to an import "C"
// declaration. It handles both the common // form and multiline /* */ form
// without interpreting comment-looking text elsewhere in the source.
func cgoPreambleLines(source *sourceFile) []cgoPreambleLine {
	groups := map[*ast.CommentGroup]bool{}
	for _, declaration := range source.AST.Decls {
		imports, ok := declaration.(*ast.GenDecl)
		if !ok || imports.Tok != token.IMPORT {
			continue
		}
		containsC := false
		for _, rawSpec := range imports.Specs {
			spec, ok := rawSpec.(*ast.ImportSpec)
			if !ok {
				continue
			}
			value, err := strconv.Unquote(spec.Path.Value)
			if err != nil || value != "C" {
				continue
			}
			containsC = true
			if spec.Doc != nil {
				groups[spec.Doc] = true
			}
			if spec.Comment != nil {
				groups[spec.Comment] = true
			}
		}
		if containsC && imports.Doc != nil {
			groups[imports.Doc] = true
		}
	}

	var lines []cgoPreambleLine
	for group := range groups {
		for _, comment := range group.List {
			position := source.FileSet.Position(comment.Slash)
			if strings.HasPrefix(comment.Text, "//") {
				text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
				if text != "" {
					lines = append(lines, cgoPreambleLine{Text: text, Line: position.Line, Column: position.Column, EndColumn: position.Column + len(comment.Text)})
				}
				continue
			}
			if !strings.HasPrefix(comment.Text, "/*") {
				continue
			}
			parts := strings.Split(comment.Text, "\n")
			for index, part := range parts {
				if index == 0 {
					part = strings.TrimPrefix(part, "/*")
				}
				if index == len(parts)-1 {
					part = strings.TrimSuffix(part, "*/")
				}
				part = strings.TrimSpace(part)
				part = strings.TrimSpace(strings.TrimPrefix(part, "*"))
				if part == "" {
					continue
				}
				column := 1
				if index == 0 {
					column = position.Column
				}
				lines = append(lines, cgoPreambleLine{Text: part, Line: position.Line + index, Column: column, EndColumn: column + len(part)})
			}
		}
	}
	sort.Slice(lines, func(i, j int) bool {
		if lines[i].Line != lines[j].Line {
			return lines[i].Line < lines[j].Line
		}
		if lines[i].Column != lines[j].Column {
			return lines[i].Column < lines[j].Column
		}
		return lines[i].Text < lines[j].Text
	})
	return lines
}

func parseCgoDirective(line string) (directive, arguments string, condition Condition, ok bool) {
	if !strings.HasPrefix(line, "#cgo ") {
		return "", "", AlwaysCondition(), false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "#cgo"))
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return "", "", AlwaysCondition(), false
	}
	head := strings.Fields(strings.TrimSpace(rest[:colon]))
	if len(head) == 0 {
		return "", "", AlwaysCondition(), false
	}
	directive = head[len(head)-1]
	arguments = strings.TrimSpace(rest[colon+1:])
	var options []Condition
	for _, expression := range head[:len(head)-1] {
		var terms []Condition
		for _, rawTerm := range strings.Split(expression, ",") {
			term := strings.TrimSpace(rawTerm)
			if term == "" {
				continue
			}
			if strings.HasPrefix(term, "!") && len(term) > 1 {
				child := buildTagCondition(strings.TrimPrefix(term, "!"))
				terms = append(terms, Condition{Op: "not", Condition: &child})
			} else {
				terms = append(terms, buildTagCondition(term))
			}
		}
		if len(terms) > 0 {
			options = append(options, canonicalCondition(Condition{Op: "all", Conditions: terms}))
		}
	}
	if len(options) == 0 {
		return directive, arguments, AlwaysCondition(), true
	}
	return directive, arguments, canonicalCondition(Condition{Op: "any", Conditions: options}), true
}

func cgoLibraries(arguments string) []string {
	seen := map[string]bool{}
	var libraries []string
	for _, field := range strings.Fields(arguments) {
		if !strings.HasPrefix(field, "-l") || len(field) <= 2 {
			continue
		}
		library := strings.TrimPrefix(field, "-l")
		if library == "" || seen[library] {
			continue
		}
		seen[library] = true
		libraries = append(libraries, library)
	}
	sort.Strings(libraries)
	return libraries
}

func parseBuildCondition(source []byte) (Condition, string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(source))
	var goBuild string
	var plusBuild []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "package ") {
			break
		}
		if strings.HasPrefix(line, "//go:build ") {
			goBuild = line
		}
		if strings.HasPrefix(line, "// +build ") {
			plusBuild = append(plusBuild, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return AlwaysCondition(), "", err
	}
	if goBuild != "" {
		expr, err := constraint.Parse(goBuild)
		if err != nil {
			return AlwaysCondition(), goBuild, err
		}
		return conditionFromConstraint(expr), strings.TrimSpace(strings.TrimPrefix(goBuild, "//go:build")), nil
	}
	if len(plusBuild) > 0 {
		conditions := make([]Condition, 0, len(plusBuild))
		texts := make([]string, 0, len(plusBuild))
		for _, line := range plusBuild {
			expr, err := constraint.Parse(line)
			if err != nil {
				return AlwaysCondition(), strings.Join(texts, " && "), err
			}
			conditions = append(conditions, conditionFromConstraint(expr))
			texts = append(texts, strings.TrimSpace(strings.TrimPrefix(line, "// +build")))
		}
		return canonicalCondition(Condition{Op: "all", Conditions: conditions}), strings.Join(texts, " && "), nil
	}
	return AlwaysCondition(), "", nil
}

func conditionFromConstraint(expr constraint.Expr) Condition {
	switch value := expr.(type) {
	case *constraint.TagExpr:
		return buildTagCondition(value.Tag)
	case *constraint.NotExpr:
		condition := conditionFromConstraint(value.X)
		return Condition{Op: "not", Condition: &condition}
	case *constraint.AndExpr:
		return canonicalCondition(Condition{Op: "all", Conditions: []Condition{conditionFromConstraint(value.X), conditionFromConstraint(value.Y)}})
	case *constraint.OrExpr:
		return canonicalCondition(Condition{Op: "any", Conditions: []Condition{conditionFromConstraint(value.X), conditionFromConstraint(value.Y)}})
	default:
		return AlwaysCondition()
	}
}

func splitDirectiveArguments(input string) ([]string, error) {
	var result []string
	for len(strings.TrimSpace(input)) > 0 {
		input = strings.TrimSpace(input)
		if input[0] == '`' || input[0] == '"' {
			quote := input[0]
			end := 1
			escaped := false
			for end < len(input) {
				if quote == '"' && input[end] == '\\' && !escaped {
					escaped = true
					end++
					continue
				}
				if input[end] == quote && !escaped {
					break
				}
				escaped = false
				end++
			}
			if end >= len(input) {
				return nil, fmt.Errorf("unterminated quoted go:embed pattern")
			}
			value, err := strconv.Unquote(input[:end+1])
			if err != nil {
				return nil, err
			}
			result = append(result, value)
			input = input[end+1:]
			continue
		}
		end := strings.IndexAny(input, " \t")
		if end < 0 {
			result = append(result, input)
			break
		}
		result = append(result, input[:end])
		input = input[end:]
	}
	return result, nil
}

func moduleForPath(modules []Module, path string) *Module {
	best := -1
	for i := range modules {
		if !isWithinRoot(modules[i].Dir, path) {
			continue
		}
		if best == -1 || len(modules[i].Dir) > len(modules[best].Dir) {
			best = i
		}
	}
	if best < 0 {
		return nil
	}
	return &modules[best]
}

func resolveLocalGroups(source *sourceFile, importPath string, groups map[string][]*packageGroup, resolution localModuleResolution) []*packageGroup {
	vendorRoot := filepath.Join(source.Module.Dir, "vendor")
	var vendor []*packageGroup
	var ordinary []*packageGroup
	for _, group := range groups[importPath] {
		if !resolution.directlyVisible(source.Module.Dir, group.Module.Dir) {
			continue
		}
		if isWithinRoot(vendorRoot, group.Dir) {
			vendor = append(vendor, group)
		} else {
			ordinary = append(ordinary, group)
		}
	}
	if len(vendor) > 0 {
		sort.Slice(vendor, func(i, j int) bool { return vendor[i].PackageNode.ID < vendor[j].PackageNode.ID })
		return vendor
	}
	if targetDir, rewritten, replaced := resolution.replacementImport(source.Module.Dir, importPath); replaced {
		var targets []*packageGroup
		for _, group := range groups[rewritten] {
			if group.Module.Dir == targetDir {
				targets = append(targets, group)
			}
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i].PackageNode.ID < targets[j].PackageNode.ID })
		return targets
	}
	sort.Slice(ordinary, func(i, j int) bool { return ordinary[i].PackageNode.ID < ordinary[j].PackageNode.ID })
	return ordinary
}

func packageImportPath(root string, module Module, dir string) string {
	normalized := cleanSlash(dir)
	marker := "/vendor/"
	if index := strings.LastIndex(normalized, marker); index >= 0 {
		return strings.TrimPrefix(normalized[index+len(marker):], "/")
	}
	if strings.HasSuffix(normalized, "/vendor") {
		return "vendor"
	}
	rel, err := filepath.Rel(module.Dir, dir)
	if err != nil || rel == "." {
		return module.Path
	}
	if strings.HasPrefix(rel, "..") {
		rootRel := relativePath(root, dir)
		return "local.invalid/" + strings.TrimPrefix(rootRel, "./")
	}
	return strings.TrimSuffix(module.Path, "/") + "/" + cleanSlash(rel)
}

func isVendorDirectory(root, dir string) bool {
	rel := "/" + cleanSlash(relativePath(root, dir)) + "/"
	return strings.Contains(rel, "/vendor/")
}

func variantsForGroup(group *packageGroup) []string {
	hasNormal := false
	hasInternal := false
	hasExternal := false
	for _, source := range group.Files {
		if !source.IsTest {
			hasNormal = true
			continue
		}
		if source.PackageName == group.BaseName {
			hasInternal = true
		} else {
			hasExternal = true
		}
	}
	var variants []string
	if hasNormal || hasInternal {
		variants = append(variants, "normal")
	}
	if hasInternal {
		variants = append(variants, "internal_test")
	}
	if hasExternal {
		variants = append(variants, "external_test")
	}
	if len(variants) == 0 {
		variants = append(variants, "normal")
	}
	return variants
}

func buildConditionFromFilename(name string) (Condition, string, bool) {
	base := strings.TrimSuffix(name, ".go")
	base = strings.TrimSuffix(base, "_test")
	parts := strings.Split(base, "_")
	if len(parts) < 2 {
		return Condition{}, "", false
	}
	goos := map[string]bool{
		"aix": true, "android": true, "darwin": true, "dragonfly": true, "freebsd": true, "hurd": true,
		"illumos": true, "ios": true, "js": true, "linux": true, "netbsd": true, "openbsd": true,
		"plan9": true, "solaris": true, "wasip1": true, "windows": true,
	}
	goarch := map[string]bool{
		"386": true, "amd64": true, "arm": true, "arm64": true, "loong64": true, "mips": true,
		"mips64": true, "mips64le": true, "mipsle": true, "ppc64": true, "ppc64le": true,
		"riscv64": true, "s390x": true, "wasm": true,
	}
	last := parts[len(parts)-1]
	conditions := []Condition{}
	labels := []string{}
	if goarch[last] {
		conditions = append(conditions, buildTagCondition(last))
		labels = append(labels, last)
		if len(parts) >= 3 {
			previous := parts[len(parts)-2]
			if goos[previous] {
				conditions = append(conditions, buildTagCondition(previous))
				labels = append(labels, previous)
			}
		}
	} else if goos[last] {
		conditions = append(conditions, buildTagCondition(last))
		labels = append(labels, last)
	}
	if len(conditions) == 0 {
		return Condition{}, "", false
	}
	sort.Strings(labels)
	if len(conditions) == 1 {
		return conditions[0], labels[0], true
	}
	return canonicalCondition(Condition{Op: "all", Conditions: conditions}), strings.Join(labels, " && "), true
}

func combineConditions(left, right Condition) Condition {
	isAlways := func(condition Condition) bool {
		return condition.Op == "all" && len(condition.Conditions) == 0 && condition.Condition == nil && condition.Key == "" && condition.Value == ""
	}
	if isAlways(left) {
		return canonicalCondition(right)
	}
	if isAlways(right) {
		return canonicalCondition(left)
	}
	return canonicalCondition(Condition{Op: "all", Conditions: []Condition{left, right}})
}

func joinConditionText(left, right string) string {
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}
	return left + " && " + right
}

func deduplicateSortedStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func variantsForFile(group *packageGroup, source *sourceFile) []string {
	if !source.IsTest {
		variants := []string{"normal"}
		if _, ok := group.Variants["internal_test"]; ok {
			variants = append(variants, "internal_test")
		}
		if _, ok := group.Variants["external_test"]; ok {
			variants = append(variants, "external_test")
		}
		return variants
	}
	if source.PackageName == group.BaseName {
		return []string{"internal_test"}
	}
	return []string{"external_test"}
}

func importSiteKind(spec *ast.ImportSpec) string {
	if spec.Name != nil && spec.Name.Name == "_" {
		return "side_effect_import"
	}
	return "import"
}

func importEdgeKind(spec *ast.ImportSpec) string {
	if spec.Name != nil && spec.Name.Name == "_" {
		return "side_effect_imports"
	}
	return "imports"
}

func edgeKindForSite(kind string) string {
	switch kind {
	case "embed":
		return "loads"
	case "cgo_import", "cgo_library":
		return "links"
	case "cgo_header":
		return "build_depends_on"
	case "module_requirement":
		return "depends_on"
	case "side_effect_import":
		return "side_effect_imports"
	default:
		return "imports"
	}
}

func hasCgoImport(file *ast.File) bool {
	for _, spec := range file.Imports {
		if value, err := strconv.Unquote(spec.Path.Value); err == nil && value == "C" {
			return true
		}
	}
	return false
}

func looksLikeStandardLibrary(importPath string) bool {
	first := importPath
	if slash := strings.IndexByte(first, '/'); slash >= 0 {
		first = first[:slash]
	}
	return !strings.Contains(first, ".")
}

func findReplacement(replacements map[string]Replacement, requirement Requirement) (Replacement, bool) {
	if replacement, ok := replacements[requirement.Path+"@"+requirement.Version]; ok {
		return replacement, true
	}
	replacement, ok := replacements[requirement.Path+"@"]
	return replacement, ok
}

func sourceEvidence(path string, startLine, startColumn, endLine, endColumn int, snippet string) []Evidence {
	return []Evidence{{
		Kind: "source", Extractor: "go-static-worker", ExtractorVersion: AdapterVersion,
		Path: cleanSlash(path), StartLine: startLine, StartColumn: startColumn,
		EndLine: endLine, EndColumn: endColumn, Detail: snippet, Properties: map[string]any{},
	}}
}

func buildTagCondition(tag string) Condition {
	return Condition{Op: "defined", Key: "go.build_tag:" + tag}
}

func isGenerated(source []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(source))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "package ") {
			return false
		}
		if strings.HasPrefix(line, "// Code generated ") && strings.HasSuffix(line, " DO NOT EDIT.") {
			return true
		}
	}
	return false
}

func configuredGoTags() []string {
	var config struct {
		GoTags []string `json:"go_tags"`
	}
	if raw := os.Getenv("DEPGRAPH_PROFILE_CONFIG"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &config)
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(config.GoTags))
	for _, tag := range config.GoTags {
		tag = strings.TrimSpace(tag)
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		result = append(result, tag)
	}
	sort.Strings(result)
	return result
}

func goProfileID(goos, goarch, cgo string, tags []string) string {
	seen := map[string]bool{}
	canonicalTags := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		canonicalTags = append(canonicalTags, tag)
	}
	sort.Strings(canonicalTags)
	parts := []string{
		"command=scan",
		"target=" + strings.TrimSpace(goos) + "-" + strings.TrimSpace(goarch),
		"cgo=" + strings.TrimSpace(cgo),
		"variants=normal,internal_test,external_test",
	}
	for _, tag := range canonicalTags {
		parts = append(parts, "tag="+tag)
	}
	return stableID("profile", "go-profile-v1", parts...)
}
