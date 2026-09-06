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
// scheduler.  The request selects work inside the repository; it never
// changes the repository root supplied to the worker.
const AnalysisUnitContractVersion = "depgraph-analysis-unit-v1"

const maxAnalysisUnitRequestBytes = 4 << 20
const maxAnalysisUnitPathLength = 4_096

type AnalysisUnitStage string

const (
	AnalysisUnitStageSyntax   AnalysisUnitStage = "syntax"
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
	ContractVersion string            `json:"contract_version"`
	UnitID          string            `json:"unit_id"`
	Adapter         string            `json:"adapter"`
	UnitRoot        string            `json:"unit_root"`
	SourcePaths     []string          `json:"source_paths"`
	Stage           AnalysisUnitStage `json:"stage"`
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
	if request.ContractVersion != AnalysisUnitContractVersion {
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
	if request.Stage != AnalysisUnitStageSyntax && request.Stage != AnalysisUnitStageSemantic {
		return fmt.Errorf("analysis unit request stage must be syntax or semantic")
	}
	if !sort.StringsAreSorted(request.SourcePaths) {
		return fmt.Errorf("analysis unit request source_paths must be sorted")
	}
	seen := make(map[string]struct{}, len(request.SourcePaths))
	for _, sourcePath := range request.SourcePaths {
		if err := validateRepositoryRelativeRequestPath("source_paths", sourcePath, false); err != nil {
			return err
		}
		if _, duplicate := seen[sourcePath]; duplicate {
			return fmt.Errorf("analysis unit request source_paths contains a duplicate path")
		}
		seen[sourcePath] = struct{}{}
		if !request.ownsPath(sourcePath) {
			return fmt.Errorf("analysis unit request source path %q escapes unit_root %q", sourcePath, request.UnitRoot)
		}
		if !strings.HasSuffix(sourcePath, ".go") {
			return fmt.Errorf("analysis unit request source path %q is not a Go source", sourcePath)
		}
	}
	return nil
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
