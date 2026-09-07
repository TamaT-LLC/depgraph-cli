package worker

import (
	"fmt"
	"sort"
	"strings"
)

// AnalysisSplitContractVersion is the pre-split planning contract the core
// attaches to a depgraph-analysis-unit-v2 request as the optional `split`
// object. The core sends it only to workers that advertise
// AnalysisLoaderScopeCapability; this worker validates and echoes the binding
// so a bounded package loader can be introduced without a request change.
const AnalysisSplitContractVersion = "depgraph-analysis-split-plan-v1"

// AnalysisLoaderScopeCapability is the handshake capability a worker
// advertises once it honours the loader scope of the `split` binding: it
// loads at least the requested loader paths, never fewer, and reports whether
// it had to load more. This worker honours `module` bindings with the
// module-whole-program load and `package` bindings with the hybrid loader.
const AnalysisLoaderScopeCapability = "analysis-loader-scope-v1"

// AnalysisGoPackageLoaderCapability tells the core planner that the worker can
// type-check a bounded set of packages with declaration-level references from
// export data and stage the bodies of a large package across semantic chunks.
const AnalysisGoPackageLoaderCapability = "analysis-go-package-loader-v1"

// Loader-scope outcomes echoed in the `analysis_loader_scope` profile property.
const (
	AnalysisLoaderScopeApplied = "applied"
	AnalysisLoaderScopeWidened = "widened"
)

const maxAnalysisSplitPaths = 1_000_000

// AnalysisSplitBinding is the request-level projection of one execution unit
// of the core's split plan. Estimates and budgets stay in the core; the
// worker only receives the loader target and the identity it must echo.
type AnalysisSplitBinding struct {
	ContractVersion string                `json:"contract_version"`
	SplitPlanID     string                `json:"split_plan_id"`
	ExecutionUnitID string                `json:"execution_unit_id"`
	SplitKind       string                `json:"split_kind"`
	Loader          AnalysisLoaderBinding `json:"loader"`
}

// AnalysisLoaderBinding names what the worker's loader must read completely
// (`paths`, `package_roots`) and what it may read for reference only.
type AnalysisLoaderBinding struct {
	Kind           string   `json:"kind"`
	Paths          []string `json:"paths"`
	PackageRoots   []string `json:"package_roots"`
	ReferenceDepth string   `json:"reference_depth"`
	ReferencePaths []string `json:"reference_paths"`
	InputSplit     bool     `json:"input_split"`
}

var analysisSplitKinds = map[string]struct{}{
	"whole": {}, "output_batch": {}, "input_batch": {}, "staged_bodies": {},
}

var analysisLoaderKinds = map[string]struct{}{
	"files": {}, "package": {}, "module": {}, "project": {}, "repository": {},
}

var analysisReferenceDepths = map[string]struct{}{
	"paths_only": {}, "declarations": {}, "bodies": {},
}

// Validate checks the binding against the request it is attached to. Every
// owned source path must be inside the loader scope, reference paths must be
// disjoint from loaded paths, and `input_split` must agree with the presence
// of reference-only inputs so an output-only split cannot pose as a bounded
// loader.
func (binding AnalysisSplitBinding) Validate(request AnalysisUnitRequest) error {
	if binding.ContractVersion != AnalysisSplitContractVersion {
		return fmt.Errorf("analysis unit request split contract version is unsupported")
	}
	if !boundedRequestString(binding.SplitPlanID) {
		return fmt.Errorf("analysis unit request split_plan_id is empty or exceeds its limit")
	}
	if !boundedRequestString(binding.ExecutionUnitID) {
		return fmt.Errorf("analysis unit request execution_unit_id is empty or exceeds its limit")
	}
	if _, ok := analysisSplitKinds[binding.SplitKind]; !ok {
		return fmt.Errorf("analysis unit request split_kind %q is unsupported", binding.SplitKind)
	}
	loader := binding.Loader
	if _, ok := analysisLoaderKinds[loader.Kind]; !ok {
		return fmt.Errorf("analysis unit request split loader kind %q is unsupported", loader.Kind)
	}
	if _, ok := analysisReferenceDepths[loader.ReferenceDepth]; !ok {
		return fmt.Errorf("analysis unit request split reference_depth %q is unsupported", loader.ReferenceDepth)
	}
	if len(loader.Paths)+len(loader.ReferencePaths)+len(loader.PackageRoots) > maxAnalysisSplitPaths {
		return fmt.Errorf("analysis unit request split loader exceeds its path limit")
	}
	if err := validateRequestPathList("split.loader.paths", loader.Paths, true); err != nil {
		return err
	}
	if err := validateRequestPathList("split.loader.reference_paths", loader.ReferencePaths, true); err != nil {
		return err
	}
	if err := validateRequestRootList("split.loader.package_roots", loader.PackageRoots); err != nil {
		return err
	}
	loaded := make(map[string]struct{}, len(loader.Paths))
	for _, loadedPath := range loader.Paths {
		if !strings.HasSuffix(loadedPath, ".go") {
			return fmt.Errorf("analysis unit request split loader path %q is not a Go source", loadedPath)
		}
		loaded[loadedPath] = struct{}{}
	}
	for _, referencePath := range loader.ReferencePaths {
		if _, duplicate := loaded[referencePath]; duplicate {
			return fmt.Errorf("analysis unit request split reference path %q is also a loader path", referencePath)
		}
	}
	for _, sourcePath := range request.SourcePaths {
		if _, ok := loaded[sourcePath]; !ok {
			return fmt.Errorf("analysis unit request source path %q is not included in split.loader.paths", sourcePath)
		}
	}
	if loader.InputSplit != (len(loader.ReferencePaths) > 0) {
		return fmt.Errorf("analysis unit request split input_split does not match its reference paths")
	}
	if binding.SplitKind == "whole" && request.ChunkCount != 1 {
		return fmt.Errorf("analysis unit request split_kind whole requires a single chunk")
	}
	if binding.SplitKind != "whole" && request.ChunkCount < 2 {
		return fmt.Errorf("analysis unit request split_kind %q requires more than one chunk", binding.SplitKind)
	}
	return nil
}

func validateRequestRootList(field string, values []string) error {
	if !sort.StringsAreSorted(values) {
		return fmt.Errorf("analysis unit request %s must be sorted", field)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validateRepositoryRelativeRequestPath(field, value, true); err != nil {
			return err
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("analysis unit request %s contains a duplicate path", field)
		}
		seen[value] = struct{}{}
	}
	return nil
}

// packageScoped reports whether the request binds its typed or semantic load
// to the package-scoped hybrid loader instead of the module-whole-program path.
func (request AnalysisUnitRequest) packageScoped() bool {
	return request.Split != nil && request.Stage != AnalysisUnitStageSyntax && request.Split.Loader.Kind == "package"
}

// stagedBodies reports whether this semantic chunk owns the bodies of a subset
// of the files its loader reads: the other files of the same packages
// contribute declarations only, as the `declarations` reference depth allows.
func (request AnalysisUnitRequest) stagedBodies() bool {
	return request.packageScoped() && request.Stage == AnalysisUnitStageSemantic && request.Split.SplitKind == "staged_bodies"
}

// scanOptions maps the negotiated split binding onto the loader selection. A
// `package` binding on a typed or semantic request selects the hybrid loader
// for the bound package roots; every other binding, a legacy request, and an
// unbound request keep the historical module-whole-program path unchanged.
// The scan-scoped build cache directory is a process input from the core, not
// part of the request contract, so it is supplied separately.
func (request AnalysisUnitRequest) scanOptions(buildCacheDir string) scanOptions {
	options := scanOptions{buildCacheDir: buildCacheDir}
	if !request.packageScoped() {
		return options
	}
	options.loaderMode = goLoaderModePackage
	options.loaderTargets = make([]goLoaderTargetSpec, 0, len(request.Split.Loader.PackageRoots))
	for _, root := range request.Split.Loader.PackageRoots {
		options.loaderTargets = append(options.loaderTargets, goLoaderTargetSpec{Dir: root})
	}
	if request.stagedBodies() {
		options.bodyPaths = make(map[string]bool, len(request.SourcePaths))
		for _, sourcePath := range request.SourcePaths {
			options.bodyPaths[sourcePath] = true
		}
	}
	return options
}

// loaderScopeOutcome reports how this worker's actual loading relates to the
// requested loader scope. Syntax requests parse exactly the requested files. A
// `module` binding is applied by the module-whole-program load. A `package`
// binding is applied when the hybrid loader bounded the load to the target
// packages and satisfied every dependency from export data; it is widened when
// a test-recompiled dependency variant had to be read from source, or when a
// narrower `files` request was honoured by loading its packages.
func (request AnalysisUnitRequest) loaderScopeOutcome(mode goLoaderMode, loaded goPackagesInventory) string {
	if request.Split == nil {
		return ""
	}
	kind := request.Split.Loader.Kind
	switch request.Stage {
	case AnalysisUnitStageSyntax:
		if kind == "files" {
			return AnalysisLoaderScopeApplied
		}
	default:
		switch kind {
		case "module", "repository", "project":
			return AnalysisLoaderScopeApplied
		case "package":
			if mode == goLoaderModePackage && (loaded.Loader == nil || loaded.Loader.Metrics.ReferencesSource == 0) {
				return AnalysisLoaderScopeApplied
			}
		}
	}
	return AnalysisLoaderScopeWidened
}

// splitProfileProperties echoes the binding identity so the core can join the
// stream to its execution unit and see whether the loader scope was applied.
func (request AnalysisUnitRequest) splitProfileProperties(outcome string) map[string]string {
	if request.Split == nil {
		return nil
	}
	return map[string]string{
		"analysis_split_contract":     request.Split.ContractVersion,
		"analysis_split_plan_id":      request.Split.SplitPlanID,
		"analysis_execution_unit_id":  request.Split.ExecutionUnitID,
		"analysis_split_kind":         request.Split.SplitKind,
		"analysis_loader_kind":        request.Split.Loader.Kind,
		"analysis_loader_input_split": fmt.Sprintf("%t", request.Split.Loader.InputSplit),
		"analysis_loader_scope":       outcome,
	}
}
