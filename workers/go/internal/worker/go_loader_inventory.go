package worker

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/tools/go/packages"
)

// goLoaderReport is the loader evidence carried by a typed inventory that the
// package-scope hybrid loader produced. Core consumes it as profile properties
// to prove that the loaded input actually shrank.
type goLoaderReport struct {
	Mode                 goLoaderMode
	ProgramScope         goSSAProgramScope
	Metrics              goLoaderMetrics
	ReferenceFingerprint goReferenceFingerprint
	References           []goLoaderReference
}

func loadGoPackagesInventoryPackageScope(root string, modules []Module, targets []goLoaderTargetSpec, work WorkFile, tags []string, buildCacheDir string, progress AnalysisProgressFunc) goPackagesInventory {
	return loadGoPackagesInventoryPackageScopeWith(root, modules, targets, work, tags, buildCacheDir, packages.Load, goPackagesLoadTimeout, progress)
}

// loadGoPackagesInventoryPackageScopeWith runs the hybrid loader for the
// target packages of exactly one discovered module and adapts the outcome to
// the goPackagesInventory contract consumed by the scanner. The dependency
// snapshot is computed from the module-wide metadata listing so every chunk of
// the module derives the same base profile identity.
func loadGoPackagesInventoryPackageScopeWith(root string, modules []Module, targets []goLoaderTargetSpec, work WorkFile, tags []string, buildCacheDir string, loader goPackagesLoadFunc, timeout time.Duration, progress AnalysisProgressFunc) (inventory goPackagesInventory) {
	inventory = goPackagesInventory{Status: "fallback", Fallback: true}
	dependencySnapshot := newGoDependencySnapshotBuilder(root, modules, work)
	defer func() {
		inventory.DependencySnapshot = dependencySnapshot.finalize(inventory.Status)
	}()

	var module *Module
	for _, target := range targets {
		candidate := moduleForPath(modules, filepath.Join(root, filepath.FromSlash(target.Dir)))
		if candidate == nil || candidate.ManifestPath == "" {
			inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(root, "go_loader_scope_invalid", "warning",
				fmt.Sprintf("target directory %q does not belong to a discovered Go module; the static parser inventory was retained", target.Dir)))
			return inventory
		}
		if module == nil {
			module = candidate
		} else if module.Dir != candidate.Dir {
			inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(root, "go_loader_scope_invalid", "warning",
				fmt.Sprintf("target directory %q belongs to a different module than %q; the static parser inventory was retained", target.Dir, module.RelativeDir)))
			return inventory
		}
	}
	if module == nil {
		inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(root, "go_loader_scope_invalid", "warning",
			"the loader scope selects no target packages; the static parser inventory was retained"))
		return inventory
	}

	knownModuleDirs := make(map[string]bool, len(modules))
	for _, candidate := range modules {
		knownModuleDirs[canonicalPathForConfinement(candidate.Dir)] = true
	}
	preflights := make(map[string]goModulePreflight, len(modules))
	for _, candidate := range modules {
		if candidate.ManifestPath == "" {
			continue
		}
		if reason := moduleUnsafeForGoPackages(root, candidate, knownModuleDirs); reason != "" {
			preflights[canonicalPathForConfinement(candidate.Dir)] = goModulePreflight{Code: "go_packages_module_confined_fallback", Reason: reason}
			continue
		}
		if reason := moduleSourceConfinementIssue(candidate, knownModuleDirs); reason != "" {
			preflights[canonicalPathForConfinement(candidate.Dir)] = goModulePreflight{Code: "go_packages_source_confinement", Reason: reason}
		}
	}
	propagateUnsafeLocalReplacements(root, modules, preflights)
	if preflight := preflights[canonicalPathForConfinement(module.Dir)]; preflight.Reason != "" {
		inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
			Code: preflight.Code, Severity: "warning", Recoverable: true, Path: relativePath(root, module.ManifestPath),
			Message: normalizeGoPackagesMessage(root, preflight.Reason+"; go/packages was not invoked and the static parser inventory was retained for this module"),
		})
		return inventory
	}

	goWork := ""
	var removeIsolatedWork func()
	if work.Path != "" {
		workPath, workSafe, workReason := confinedWorkFile(root, work)
		sourceWorkPath := workPath
		if !workSafe {
			sourceWorkPath = lexicalWorkspacePath(root, work.Path)
		}
		if sourceWorkPath != "" && moduleIsWorkspaceMember(root, *module, work, sourceWorkPath) {
			if !workSafe {
				inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(root, "go_packages_workspace_disabled", "warning",
					workReason+"; go/packages was not invoked for parsed workspace members and the parser retained workspace syntax"))
				return inventory
			}
			if reason := workspaceModulesUnsafeForGoPackages(root, modules, work, sourceWorkPath, knownModuleDirs); reason != "" {
				inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(root, "go_packages_workspace_disabled", "warning",
					"go.work could not be isolated safely: "+reason+"; go/packages was not invoked for workspace members and the parser retained workspace syntax"))
				return inventory
			}
			if reason := unsafeWorkspaceReplacementReason(root, work, sourceWorkPath, preflights); reason != "" {
				inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(root, "go_packages_workspace_disabled", "warning",
					"go.work replacement is unsafe for typed loading: "+reason+"; go/packages was not invoked for workspace members and the parser retained workspace syntax"))
				return inventory
			}
			isolated, cleanup, err := isolatedGoWorkFile(root, work, sourceWorkPath)
			if err != nil {
				inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(root, "go_packages_workspace_disabled", "warning",
					"go.work could not be isolated outside the scan root: "+err.Error()+"; go/packages was not invoked for workspace members and the parser retained workspace syntax"))
				return inventory
			}
			goWork = isolated
			removeIsolatedWork = cleanup
		}
	}
	if removeIsolatedWork != nil {
		defer removeIsolatedWork()
	}

	session, err := openGoLoaderSession(root, buildCacheDir, loader, timeout)
	if err != nil {
		code := "go_packages_environment"
		if strings.Contains(err.Error(), "build cache") {
			code = "go_loader_build_cache_rejected"
		}
		inventory.Diagnostics = append(inventory.Diagnostics, goPackagesDiagnostic(root, code, "warning",
			fmt.Sprintf("go/packages was not invoked: %v; the static parser inventory was retained", err)))
		return inventory
	}
	defer session.close()
	dependencySnapshot.setModuleCache(session.environment.ModuleCache)

	result := session.loadPackageScope(goLoaderScope{
		Module: *module, Modules: modules, Targets: targets, Tags: tags, Work: goWork,
	}, progress)
	for _, diagnostic := range result.Diagnostics {
		inventory.Diagnostics = append(inventory.Diagnostics, diagnostic)
	}
	inventory.Loader = &goLoaderReport{
		Mode: goLoaderModePackage, ProgramScope: goSSAProgramScopePackage, Metrics: result.Metrics,
		ReferenceFingerprint: result.ReferenceFingerprint, References: result.References,
	}
	if result.Listing != nil {
		if reasons := dependencySnapshot.observeModuleLoad(*module, result.Listing); len(reasons) > 0 {
			inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
				Code: "go_dependency_snapshot_incomplete", Severity: "warning", Recoverable: true,
				Path:    relativePath(root, module.ManifestPath),
				Message: "offline dependency source snapshot was incomplete (" + strings.Join(reasons, ",") + "); typed packages for this module were discarded",
			})
			result.Status = "fallback"
		}
	}
	activeFiles := map[string]bool{}
	compiledFiles := map[string]bool{}
	embedFiles := map[string]bool{}
	testVariants := 0
	for _, target := range result.Targets {
		if target.ForTest != "" {
			testVariants++
		}
		for _, file := range target.GoFiles {
			if confined, ok := confinedMetadataFile(root, file); ok {
				activeFiles[confined] = true
			}
		}
		for _, file := range target.CompiledGoFiles {
			if confined, ok := confinedMetadataFile(root, file); ok {
				compiledFiles[confined] = true
			}
		}
		for _, file := range target.EmbedFiles {
			if confined, ok := confinedMetadataFile(root, file); ok {
				embedFiles[confined] = true
			}
		}
	}
	inventory.PackageCount = len(result.Targets)
	inventory.ActiveFileCount = len(activeFiles)
	inventory.CompiledFileCount = len(compiledFiles)
	inventory.EmbedFileCount = len(embedFiles)
	inventory.TestVariantCount = testVariants
	if result.Status != "loaded" {
		inventory.Diagnostics = append(inventory.Diagnostics, Diagnostic{
			Code: "go_packages_module_fallback", Severity: "warning", Recoverable: true,
			Path:    relativePath(root, module.ManifestPath),
			Message: "go/packages typed data was incomplete for this package scope; its typed packages were discarded and the static parser inventory was retained",
		})
		return inventory
	}
	inventory.Status = "loaded"
	inventory.Fallback = false
	inventory.ModuleCount = 1
	inventory.TypedPackages = result.TypedPackages
	inventory.ReferencePackages = result.ReferencePackages
	return inventory
}

func goLoaderProperties(report *goLoaderReport) map[string]string {
	if report == nil {
		return nil
	}
	metrics := report.Metrics
	properties := map[string]string{
		"analysis_loader_mode":                       string(report.Mode),
		"go_loader_program_scope":                    string(report.ProgramScope),
		"go_loader_target_packages":                  strconv.Itoa(metrics.TargetPackages),
		"go_loader_target_files":                     strconv.Itoa(metrics.TargetFiles),
		"go_loader_target_bytes":                     strconv.FormatInt(metrics.TargetBytes, 10),
		"go_loader_loaded_packages":                  strconv.Itoa(metrics.LoadedPackages),
		"go_loader_syntax_packages":                  strconv.Itoa(metrics.SyntaxPackages),
		"go_loader_parsed_files":                     strconv.Itoa(metrics.ParsedFiles),
		"go_loader_syntax_equals_targets":            strconv.FormatBool(metrics.SyntaxPackages == metrics.TargetPackages),
		"go_loader_reference_packages_export":        strconv.Itoa(metrics.ReferencesExport),
		"go_loader_reference_packages_source":        strconv.Itoa(metrics.ReferencesSource),
		"go_loader_reference_packages_in_repo":       strconv.Itoa(metrics.ReferencesInRepo),
		"go_loader_reference_packages_external":      strconv.Itoa(metrics.ReferencesExternal),
		"go_loader_reference_packages_standard":      strconv.Itoa(metrics.ReferencesStandard),
		"go_loader_child_processes":                  strconv.Itoa(metrics.ChildProcesses),
		"go_loader_listing_ms":                       strconv.FormatInt(metrics.ListingMilliseconds, 10),
		"go_loader_export_compile_ms":                strconv.FormatInt(metrics.ExportMilliseconds, 10),
		"go_loader_type_check_ms":                    strconv.FormatInt(metrics.CheckMilliseconds, 10),
		"go_loader_build_cache_reused":               strconv.FormatBool(metrics.BuildCacheReused),
		"go_loader_witness":                          metrics.Witness,
		"go_reference_fingerprint_schema":            goReferenceFingerprintSchema,
		"go_reference_fingerprint":                   report.ReferenceFingerprint.Fingerprint,
		"go_reference_fingerprint_packages":          strconv.Itoa(report.ReferenceFingerprint.PackageCount),
		"go_reference_fingerprint_files":             strconv.Itoa(report.ReferenceFingerprint.FileCount),
		"go_packages_query":                          "targets-syntax-types-info,dependencies-export-data",
		"go_loader_child_process_kind":               "go-list-metadata,go-list-export",
		"go_loader_child_process_target_compiled":    "false",
		"go_loader_reference_source_policy":          "test-recompiled-variants-only",
		"go_loader_identity_key":                     "module-relative-dir,pkg-path,for-test",
		"go_implements_scope":                        "owned-concrete-visible-interfaces",
		"go_loader_dependency_snapshot_source":       "module-wide-metadata-listing",
		"go_loader_reference_fingerprint_definition": "transitive-in-repo-import-closure",
	}
	if metrics.BuildCacheShared {
		properties["go_loader_build_cache"] = "scan-shared"
	} else {
		properties["go_loader_build_cache"] = "invocation-private"
	}
	if metrics.ChildMaxRSSBytes > 0 {
		properties["go_loader_child_max_rss_bytes"] = strconv.FormatInt(metrics.ChildMaxRSSBytes, 10)
	}
	if metrics.SelfPeakRSSBytes > 0 {
		properties["go_loader_peak_rss_bytes"] = strconv.FormatInt(metrics.SelfPeakRSSBytes, 10)
	}
	if len(report.ReferenceFingerprint.Reasons) > 0 {
		properties["go_reference_fingerprint_reasons"] = strings.Join(report.ReferenceFingerprint.Reasons, ",")
	}
	return properties
}
