package worker

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// BenchmarkSyntheticAnalysisUnitLarge is intentionally a benchmark rather
// than a regular test. It keeps the normal worker test suite fast while
// exercising the compiler with a package large enough to expose the memory
// and scheduling shape that the analysis-unit contract is meant to handle.
// Run it explicitly with -benchtime=1x; a repeated benchmark run repeats the
// full typed load and SSA construction by design.
func BenchmarkSyntheticAnalysisUnitLarge(b *testing.B) {
	fixture := writeLargeSyntheticAnalysisFixture(b, 1024, 8, 8)
	b.Logf("fixture source_files=%d functions_per_file=%d total_functions=%d modules=%d", len(fixture.sourcePaths), fixture.functionsPerFile, len(fixture.sourcePaths)*fixture.functionsPerFile, fixture.moduleCount)

	cases := []struct {
		name string
		run  func() (Result, int, time.Duration, int64, error)
	}{
		{
			name: "syntax_single",
			run: func() (Result, int, time.Duration, int64, error) {
				request := fixture.request(fixture.sourcePaths, AnalysisUnitStageSyntax, "single", 0, 1, []string{"app/go.mod"})
				return runLargeSyntheticRequest(fixture.root, request)
			},
		},
		{
			name: "syntax_128_file_batches",
			run: func() (Result, int, time.Duration, int64, error) {
				started := time.Now()
				sampler := startSyntheticResourceSampler()
				progressEvents := 0
				var aggregate Result
				for _, request := range fixture.sourceBatchRequests(128) {
					result, err := ScanWithAnalysisUnitProgress(fixture.root, "", request, func(_, _ string, _ int) {
						progressEvents++
					})
					if err != nil {
						return Result{}, progressEvents, time.Since(started), sampler.stop(), err
					}
					aggregate.Coverage.FilesDiscovered += result.Coverage.FilesDiscovered
					aggregate.Coverage.FilesAnalyzed += result.Coverage.FilesAnalyzed
					aggregate.Coverage.FilesSkipped += result.Coverage.FilesSkipped
				}
				return aggregate, progressEvents, time.Since(started), sampler.stop(), nil
			},
		},
		{
			name: "semantic_full_module",
			run: func() (Result, int, time.Duration, int64, error) {
				request := fixture.request(fixture.sourcePaths, AnalysisUnitStageSemantic, "semantic", 0, 1, nil)
				return runLargeSyntheticRequest(fixture.root, request)
			},
		},
	}

	for _, testCase := range cases {
		b.Run(testCase.name, func(b *testing.B) {
			for iteration := 0; iteration < b.N; iteration++ {
				result, progressEvents, elapsed, peakRSS, err := testCase.run()
				if err != nil {
					b.Fatal(err)
				}
				if progressEvents == 0 {
					b.Fatal("analysis unit emitted no progress events")
				}
				if testCase.name == "semantic_full_module" {
					if result.Profile.Properties["go_packages_status"] != "loaded" {
						b.Fatalf("large semantic fixture did not load a complete typed universe: status=%q diagnostics=%v", result.Profile.Properties["go_packages_status"], result.Diagnostics)
					}
					if result.Profile.Properties["analysis_scope"] != "full_module" {
						b.Fatalf("large semantic fixture scope=%q, want full_module", result.Profile.Properties["analysis_scope"])
					}
				}
				b.ReportMetric(float64(elapsed.Microseconds()), "wall_us")
				b.ReportMetric(float64(peakRSS), "peak_rss_bytes")
				if iteration == 0 {
					b.Logf("stage=%s source_files=%d progress_events=%d elapsed_ms=%d peak_rss_bytes=%d typed_packages=%s typed_files=%s", testCase.name, len(fixture.sourcePaths), progressEvents, elapsed.Milliseconds(), peakRSS, result.Profile.Properties["go_packages_typed_packages"], result.Profile.Properties["go_packages_typed_files"])
				}
			}
		})
	}
}

func runLargeSyntheticRequest(root string, request AnalysisUnitRequest) (Result, int, time.Duration, int64, error) {
	started := time.Now()
	sampler := startSyntheticResourceSampler()
	progressEvents := 0
	result, err := ScanWithAnalysisUnitProgress(root, "", request, func(_, _ string, _ int) {
		progressEvents++
	})
	peakRSS := sampler.stop()
	return result, progressEvents, time.Since(started), peakRSS, err
}

type largeSyntheticGoFixture struct {
	root             string
	unitRoot         string
	sourcePaths      []string
	contextPaths     []string
	functionsPerFile int
	moduleCount      int
}

func writeLargeSyntheticAnalysisFixture(tb testing.TB, sourceFileCount, functionsPerFile, dependencyModuleCount int) largeSyntheticGoFixture {
	tb.Helper()
	if sourceFileCount < 1024 || functionsPerFile < 2 || dependencyModuleCount < 1 {
		tb.Fatalf("large fixture sizes are below the performance bound: files=%d functions=%d modules=%d", sourceFileCount, functionsPerFile, dependencyModuleCount)
	}
	root := filepath.Clean(mustLargeSyntheticPath(tb, tb.TempDir()))
	const (
		appModulePath  = "example.test/large/app"
		sameModulePath = "example.test/large/shared"
	)

	var appGoMod strings.Builder
	fmt.Fprintf(&appGoMod, "module %s\n\ngo 1.26.1\n\nrequire (\n", appModulePath)
	for index := 0; index < dependencyModuleCount; index++ {
		fmt.Fprintf(&appGoMod, "\texample.test/large/dep%02d v0.0.0\n", index)
	}
	fmt.Fprintf(&appGoMod, "\t%s v0.0.0\n)\n\n", sameModulePath)
	for index := 0; index < dependencyModuleCount; index++ {
		fmt.Fprintf(&appGoMod, "replace example.test/large/dep%02d => ../dep-%02d\n", index, index)
	}
	fmt.Fprintf(&appGoMod, "replace %s => ../same-a\n", sameModulePath)
	writeLargeSyntheticFile(tb, filepath.Join(root, "app", "go.mod"), appGoMod.String())

	imports := make([]string, 0, dependencyModuleCount+1)
	imports = append(imports, "shared \""+sameModulePath+"\"")
	for index := 0; index < dependencyModuleCount; index++ {
		imports = append(imports, fmt.Sprintf("dep%02d \"example.test/large/dep%02d\"", index, index))
	}
	var entry strings.Builder
	entry.WriteString("package app\n\nimport (\n\t")
	entry.WriteString(strings.Join(imports, "\n\t"))
	entry.WriteString("\n)\n\nfunc Entry() int {\n\treturn shared.Value()")
	for index := 0; index < dependencyModuleCount; index++ {
		fmt.Fprintf(&entry, " + dep%02d.Value()", index)
	}
	entry.WriteString("\n}\n")
	appendLargeSyntheticFunctions(&entry, 0, functionsPerFile)
	writeLargeSyntheticFile(tb, filepath.Join(root, "app", "file0000.go"), entry.String())
	for index := 1; index < sourceFileCount; index++ {
		var source strings.Builder
		source.WriteString("package app\n\n")
		appendLargeSyntheticFunctions(&source, index, functionsPerFile)
		writeLargeSyntheticFile(tb, filepath.Join(root, "app", fmt.Sprintf("file%04d.go", index)), source.String())
	}

	for _, relativeDir := range []string{"same-a", "same-b"} {
		writeLargeSyntheticFile(tb, filepath.Join(root, relativeDir, "go.mod"), "module "+sameModulePath+"\n\ngo 1.26.1\n")
		writeLargeSyntheticFile(tb, filepath.Join(root, relativeDir, "shared.go"), "package shared\n\nfunc Value() int { return 7 }\n")
	}
	for index := 0; index < dependencyModuleCount; index++ {
		relativeDir := fmt.Sprintf("dep-%02d", index)
		modulePath := fmt.Sprintf("example.test/large/dep%02d", index)
		packageName := fmt.Sprintf("dep%02d", index)
		writeLargeSyntheticFile(tb, filepath.Join(root, relativeDir, "go.mod"), "module "+modulePath+"\n\ngo 1.26.1\n")
		writeLargeSyntheticFile(tb, filepath.Join(root, relativeDir, "dep.go"), fmt.Sprintf("package %s\n\nfunc Value() int { return %d }\n", packageName, index+1))
	}

	sourcePaths := make([]string, 0, sourceFileCount)
	for index := 0; index < sourceFileCount; index++ {
		sourcePaths = append(sourcePaths, filepath.ToSlash(filepath.Join("app", fmt.Sprintf("file%04d.go", index))))
	}
	contextPaths := append([]string(nil), sourcePaths...)
	contextPaths = append(contextPaths, "same-a/shared.go")
	for index := 0; index < dependencyModuleCount; index++ {
		contextPaths = append(contextPaths, fmt.Sprintf("dep-%02d/dep.go", index))
	}
	sort.Strings(contextPaths)

	return largeSyntheticGoFixture{
		root: root, unitRoot: "app", sourcePaths: sourcePaths, contextPaths: contextPaths,
		functionsPerFile: functionsPerFile, moduleCount: dependencyModuleCount + 3,
	}
}

func appendLargeSyntheticFunctions(source *strings.Builder, fileIndex, functionsPerFile int) {
	for functionIndex := 0; functionIndex < functionsPerFile; functionIndex++ {
		fmt.Fprintf(source, "func Item%04d_%02d() int { return %d }\n", fileIndex, functionIndex, fileIndex*functionsPerFile+functionIndex)
	}
}

func (fixture largeSyntheticGoFixture) request(sourcePaths []string, stage AnalysisUnitStage, chunkID string, chunkIndex, chunkCount int, auxiliary []string) AnalysisUnitRequest {
	return AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:large-app",
		Adapter:            AdapterName,
		UnitRoot:           fixture.unitRoot,
		SourcePaths:        append([]string(nil), sourcePaths...),
		Stage:              stage,
		ContextPaths:       append([]string(nil), fixture.contextPaths...),
		ChunkID:            chunkID,
		ChunkIndex:         chunkIndex,
		ChunkCount:         chunkCount,
		AuxiliaryPaths:     append([]string(nil), auxiliary...),
		ContextFingerprint: "sha256:synthetic-large-analysis-context-v1",
	}
}

func (fixture largeSyntheticGoFixture) sourceBatchRequests(chunkSize int) []AnalysisUnitRequest {
	chunkCount := (len(fixture.sourcePaths) + chunkSize - 1) / chunkSize
	requests := make([]AnalysisUnitRequest, 0, chunkCount)
	for chunkIndex, start := 0, 0; start < len(fixture.sourcePaths); chunkIndex, start = chunkIndex+1, start+chunkSize {
		end := start + chunkSize
		if end > len(fixture.sourcePaths) {
			end = len(fixture.sourcePaths)
		}
		auxiliary := []string(nil)
		if chunkIndex == 0 {
			auxiliary = []string{"app/go.mod"}
		}
		requests = append(requests, fixture.request(fixture.sourcePaths[start:end], AnalysisUnitStageSyntax, fmt.Sprintf("chunk-%03d-of-%03d", chunkIndex, chunkCount), chunkIndex, chunkCount, auxiliary))
	}
	return requests
}

func writeLargeSyntheticFile(tb testing.TB, path, content string) {
	tb.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		tb.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		tb.Fatalf("write fixture file %s: %v", path, err)
	}
}

func mustLargeSyntheticPath(tb testing.TB, path string) string {
	tb.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		tb.Fatalf("canonicalize fixture root: %v", err)
	}
	return resolved
}
