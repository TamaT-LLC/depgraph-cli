package worker

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"unicode"
)

// AnalysisUnitContractVersion is the request contract negotiated by the core
// scheduler. The request selects work inside the repository; it never changes
// the repository root supplied to the worker.
const AnalysisUnitContractVersion = "depgraph-analysis-unit-v2"

// LegacyAnalysisUnitContractVersion remains readable for callers which used
// the original single-unit protocol. New workers advertise v2 only; accepting
// v1 here keeps direct library users from failing while they migrate their
// request producer.
const LegacyAnalysisUnitContractVersion = "depgraph-analysis-unit-v1"

const maxAnalysisUnitRequestBytes = 4 << 20
const maxAnalysisUnitPathLength = 4_096

type AnalysisUnitStage string

const (
	AnalysisUnitStageSyntax   AnalysisUnitStage = "syntax"
	AnalysisUnitStageTyped    AnalysisUnitStage = "typed"
	AnalysisUnitStageSemantic AnalysisUnitStage = "semantic"
)

// AnalysisProgressFunc receives bounded stage progress for an analysis-unit
// scan. The callback is intentionally optional so the legacy whole-repository
// API remains silent and unchanged.
type AnalysisProgressFunc func(phase, status string, items int)

// AnalysisUnitRequest is intentionally smaller than the planning model.  The
// core owns planning and checkpoint fingerprints; the worker only receives
// the immutable repository-relative scope and the requested phase.
type AnalysisUnitRequest struct {
	ContractVersion    string            `json:"contract_version"`
	UnitID             string            `json:"unit_id"`
	Adapter            string            `json:"adapter"`
	UnitRoot           string            `json:"unit_root"`
	SourcePaths        []string          `json:"source_paths"`
	Stage              AnalysisUnitStage `json:"stage"`
	ContextPaths       []string          `json:"context_paths"`
	ChunkID            string            `json:"chunk_id"`
	ChunkIndex         int               `json:"chunk_index"`
	ChunkCount         int               `json:"chunk_count"`
	AuxiliaryPaths     []string          `json:"auxiliary_paths"`
	ContextFingerprint string            `json:"context_fingerprint"`
	// Split is the optional pre-split planning binding
	// (depgraph-analysis-split-plan-v1). The core attaches it only after the
	// worker advertised AnalysisLoaderScopeCapability; it never changes which
	// results the request may emit, only what the loader is asked to read.
	Split *AnalysisSplitBinding `json:"split,omitempty"`
}

// ReadAnalysisUnitRequest reads and strictly validates a request file before
// the process changes into its neutral working directory.
func ReadAnalysisUnitRequest(file string) (AnalysisUnitRequest, error) {
	info, err := os.Stat(file)
	if err != nil {
		return AnalysisUnitRequest{}, fmt.Errorf("read analysis unit request: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxAnalysisUnitRequestBytes {
		return AnalysisUnitRequest{}, fmt.Errorf("analysis unit request is not a regular file within its byte limit")
	}
	handle, err := os.Open(file)
	if err != nil {
		return AnalysisUnitRequest{}, fmt.Errorf("open analysis unit request: %w", err)
	}
	defer handle.Close()
	decoder := json.NewDecoder(io.LimitReader(handle, maxAnalysisUnitRequestBytes+1))
	decoder.DisallowUnknownFields()
	var request AnalysisUnitRequest
	if err := decoder.Decode(&request); err != nil {
		return AnalysisUnitRequest{}, fmt.Errorf("decode analysis unit request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return AnalysisUnitRequest{}, fmt.Errorf("analysis unit request contains trailing data")
	}
	if err := request.Validate(); err != nil {
		return AnalysisUnitRequest{}, err
	}
	return request, nil
}

func (request AnalysisUnitRequest) Validate() error {
	if request.ContractVersion != AnalysisUnitContractVersion && request.ContractVersion != LegacyAnalysisUnitContractVersion {
		return fmt.Errorf("analysis unit request contract version is unsupported")
	}
	if request.Adapter != AdapterName {
		return fmt.Errorf("analysis unit request adapter must be %q", AdapterName)
	}
	if !boundedRequestString(request.UnitID) {
		return fmt.Errorf("analysis unit request unit_id is empty or exceeds its limit")
	}
	if err := validateRepositoryRelativeRequestPath("unit_root", request.UnitRoot, true); err != nil {
		return err
	}
	if request.Stage != AnalysisUnitStageSyntax && request.Stage != AnalysisUnitStageTyped && request.Stage != AnalysisUnitStageSemantic {
		return fmt.Errorf("analysis unit request stage must be syntax, typed, or semantic")
	}
	if request.ContractVersion == LegacyAnalysisUnitContractVersion && request.Stage == AnalysisUnitStageTyped {
		return fmt.Errorf("typed analysis unit stage requires %s", AnalysisUnitContractVersion)
	}
	if err := validateRequestPathList("source_paths", request.SourcePaths, true); err != nil {
		return err
	}
	for _, sourcePath := range request.SourcePaths {
		if !request.ownsPath(sourcePath) {
			return fmt.Errorf("analysis unit request source path %q escapes unit_root %q", sourcePath, request.UnitRoot)
		}
		if !strings.HasSuffix(sourcePath, ".go") {
			return fmt.Errorf("analysis unit request source path %q is not a Go source", sourcePath)
		}
	}
	if request.ContractVersion == LegacyAnalysisUnitContractVersion {
		if request.Split != nil {
			return fmt.Errorf("analysis unit request split requires %s", AnalysisUnitContractVersion)
		}
		return nil
	}
	if err := validateRequestPathList("context_paths", request.ContextPaths, true); err != nil {
		return err
	}
	context := request.contextPathSet()
	for _, contextPath := range request.ContextPaths {
		if !strings.HasSuffix(contextPath, ".go") {
			return fmt.Errorf("analysis unit request context path %q is not a Go source", contextPath)
		}
	}
	for _, sourcePath := range request.SourcePaths {
		if _, ok := context[sourcePath]; !ok {
			return fmt.Errorf("analysis unit request source path %q is not included in context_paths", sourcePath)
		}
	}
	if !boundedRequestString(request.ChunkID) {
		return fmt.Errorf("analysis unit request chunk_id is empty or exceeds its limit")
	}
	if request.ChunkCount <= 0 || request.ChunkIndex < 0 || request.ChunkIndex >= request.ChunkCount {
		return fmt.Errorf("analysis unit request chunk_index/count is invalid")
	}
	// A typed request loads the module as one operation unless a package
	// loader binding partitions the typed stage by package; such chunks own a
	// subset of the module sources they receive as context.
	if request.Stage == AnalysisUnitStageTyped && !request.packageScoped() {
		if request.ChunkIndex != 0 || request.ChunkCount != 1 {
			return fmt.Errorf("typed analysis unit request must use exactly one chunk")
		}
		if !sameRequestPaths(request.SourcePaths, request.ContextPaths) {
			return fmt.Errorf("typed analysis unit request source_paths must cover the complete context_paths set")
		}
	}
	if err := validateRequestPathList("auxiliary_paths", request.AuxiliaryPaths, true); err != nil {
		return err
	}
	for _, auxiliaryPath := range request.AuxiliaryPaths {
		if !request.ownsPath(auxiliaryPath) && auxiliaryPath != "go.work" {
			return fmt.Errorf("analysis unit request auxiliary path %q escapes unit_root %q", auxiliaryPath, request.UnitRoot)
		}
		if !isAnalysisAuxiliaryPath(auxiliaryPath) {
			return fmt.Errorf("analysis unit request auxiliary path %q is unsupported", auxiliaryPath)
		}
	}
	if request.Stage != AnalysisUnitStageSyntax && len(request.AuxiliaryPaths) > 0 {
		return fmt.Errorf("analysis unit request auxiliary_paths are only valid for syntax stage")
	}
	if !boundedRequestString(request.ContextFingerprint) {
		return fmt.Errorf("analysis unit request context_fingerprint is empty or exceeds its limit")
	}
	if request.Split != nil {
		if err := request.Split.Validate(request); err != nil {
			return err
		}
	}
	return nil
}

func sameRequestPaths(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateRequestPathList(field string, values []string, allowEmpty bool) error {
	if !allowEmpty && len(values) == 0 {
		return fmt.Errorf("analysis unit request %s must not be empty", field)
	}
	if !sort.StringsAreSorted(values) {
		return fmt.Errorf("analysis unit request %s must be sorted", field)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validateRepositoryRelativeRequestPath(field, value, false); err != nil {
			return err
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("analysis unit request %s contains a duplicate path", field)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func isAnalysisAuxiliaryPath(relative string) bool {
	if relative == "go.work" || path.Base(relative) == "go.mod" {
		return true
	}
	extension := strings.ToLower(path.Ext(relative))
	return extension == ".s"
}

func (request AnalysisUnitRequest) contextPathSet() map[string]struct{} {
	paths := request.ContextPaths
	if request.ContractVersion == LegacyAnalysisUnitContractVersion && len(paths) == 0 {
		paths = request.SourcePaths
	}
	set := make(map[string]struct{}, len(paths))
	for _, contextPath := range paths {
		set[contextPath] = struct{}{}
	}
	return set
}

func (request AnalysisUnitRequest) auxiliaryPathSet() map[string]struct{} {
	set := make(map[string]struct{}, len(request.AuxiliaryPaths))
	for _, path := range request.AuxiliaryPaths {
		set[path] = struct{}{}
	}
	return set
}

func (request AnalysisUnitRequest) normalized() AnalysisUnitRequest {
	if request.ContractVersion != LegacyAnalysisUnitContractVersion {
		return request
	}
	if len(request.ContextPaths) == 0 {
		request.ContextPaths = append([]string(nil), request.SourcePaths...)
	}
	if request.ChunkID == "" {
		request.ChunkID = "legacy"
	}
	if request.ChunkCount == 0 {
		request.ChunkCount = 1
	}
	return request
}

// ValidateForRoot applies checks that need the canonical repository root.  A
// unit root must resolve to a directory under the supplied root, and every
// requested source path must remain confined after symlink evaluation.
func (request AnalysisUnitRequest) ValidateForRoot(root string) error {
	if err := request.Validate(); err != nil {
		return err
	}
	root = canonicalPathForConfinement(root)
	if root == "" {
		return fmt.Errorf("analysis unit repository root could not be canonicalized")
	}
	unitPath := root
	if request.UnitRoot != "." {
		unitPath = canonicalPathForConfinement(pathJoin(root, request.UnitRoot))
	}
	if unitPath == "" || !isWithinRoot(root, unitPath) {
		return fmt.Errorf("analysis unit unit_root %q escapes repository root", request.UnitRoot)
	}
	for sourcePath := range request.sourcePathSet() {
		absolute := canonicalPathForConfinement(pathJoin(root, sourcePath))
		if absolute == "" || !isWithinRoot(unitPath, absolute) {
			return fmt.Errorf("analysis unit source path %q escapes repository root", sourcePath)
		}
	}
	for contextPath := range request.contextPathSet() {
		absolute := canonicalPathForConfinement(pathJoin(root, contextPath))
		if absolute == "" || !isWithinRoot(root, absolute) {
			return fmt.Errorf("analysis unit context path %q escapes repository root", contextPath)
		}
	}
	for auxiliaryPath := range request.auxiliaryPathSet() {
		absolute := canonicalPathForConfinement(pathJoin(root, auxiliaryPath))
		if absolute == "" || !isWithinRoot(root, absolute) {
			return fmt.Errorf("analysis unit auxiliary path %q escapes repository root", auxiliaryPath)
		}
	}
	if request.Split != nil {
		for _, loaderPath := range append(append([]string(nil), request.Split.Loader.Paths...), request.Split.Loader.ReferencePaths...) {
			absolute := canonicalPathForConfinement(pathJoin(root, loaderPath))
			if absolute == "" || !isWithinRoot(root, absolute) {
				return fmt.Errorf("analysis unit split loader path %q escapes repository root", loaderPath)
			}
		}
	}
	return nil
}

func (request AnalysisUnitRequest) ownsPath(relative string) bool {
	if request.UnitRoot == "." {
		return relative != "" && relative != "." && !strings.HasPrefix(relative, "../")
	}
	prefix := request.UnitRoot + "/"
	return strings.HasPrefix(relative, prefix) && relative != request.UnitRoot
}

func (request AnalysisUnitRequest) sourcePathSet() map[string]struct{} {
	set := make(map[string]struct{}, len(request.SourcePaths))
	for _, sourcePath := range request.SourcePaths {
		set[sourcePath] = struct{}{}
	}
	return set
}

func validateRepositoryRelativeRequestPath(field, value string, allowDot bool) error {
	if value == "." && allowDot {
		return nil
	}
	if value == "" || len(value) > maxAnalysisUnitPathLength || strings.ContainsAny(value, "\\:") || strings.HasPrefix(value, "/") ||
		strings.IndexFunc(value, unicode.IsControl) >= 0 || !path.IsAbs(value) && path.Clean(value) != value ||
		strings.HasPrefix(value, "../") || value == ".." {
		return fmt.Errorf("analysis unit request %s is not a canonical repository-relative path", field)
	}
	if !allowDot && value == "." {
		return fmt.Errorf("analysis unit request %s cannot be the repository root", field)
	}
	return nil
}

func boundedRequestString(value string) bool {
	return value != "" && len(value) <= 4096 && strings.IndexFunc(value, unicode.IsControl) < 0
}

func pathJoin(root, relative string) string {
	if relative == "." {
		return root
	}
	return root + "/" + relative
}
