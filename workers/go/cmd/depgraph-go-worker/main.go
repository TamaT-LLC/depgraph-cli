package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TamaT-LLC/depgraph-cli/workers/go/internal/worker"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("depgraph-go-worker", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root to scan")
	scanID := flags.String("scan-id", "", "scan identifier supplied by depgraph core")
	inventoryFile := flags.String("inventory-file", "", "repository inventory supplied by depgraph core")
	analysisUnitFile := flags.String("analysis-unit", "", "analysis unit request supplied by depgraph core")
	version := flags.Bool("version", false, "print worker version")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: depgraph-go-worker --root <path> --scan-id <id>")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *version {
		fmt.Fprintf(stdout, "depgraph-go-worker %s (protocol %s; capabilities %s)\n", worker.AdapterVersion, worker.ProtocolVersion, strings.Join(worker.AnalysisUnitCapabilities, ","))
		return 0
	}
	if flags.NArg() != 0 || *root == "" || *scanID == "" {
		flags.Usage()
		return 2
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintf(stderr, "depgraph-go-worker: normalize root: %v\n", err)
		return 3
	}
	inventoryPath := *inventoryFile
	if inventoryPath != "" {
		inventoryPath, err = filepath.Abs(inventoryPath)
		if err != nil {
			fmt.Fprintf(stderr, "depgraph-go-worker: normalize inventory: %v\n", err)
			return 3
		}
	}
	var analysisUnit *worker.AnalysisUnitRequest
	if *analysisUnitFile != "" {
		request, requestErr := worker.ReadAnalysisUnitRequest(*analysisUnitFile)
		if requestErr != nil {
			fmt.Fprintf(stderr, "depgraph-go-worker: %v\n", requestErr)
			if emitErr := worker.EmitFailure(stdout, *scanID, absRoot, requestErr); emitErr != nil {
				fmt.Fprintf(stderr, "depgraph-go-worker: emit failure: %v\n", emitErr)
			}
			return 3
		}
		analysisUnit = &request
	}
	neutralDirectory, err := os.MkdirTemp("", "depgraph-go-worker-")
	if err != nil {
		fmt.Fprintf(stderr, "depgraph-go-worker: create neutral working directory: %v\n", err)
		return 3
	}
	defer os.RemoveAll(neutralDirectory)
	previousDirectory, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "depgraph-go-worker: read working directory: %v\n", err)
		return 3
	}
	if err := os.Chdir(neutralDirectory); err != nil {
		fmt.Fprintf(stderr, "depgraph-go-worker: enter neutral working directory: %v\n", err)
		return 3
	}
	defer func() {
		if err := os.Chdir(previousDirectory); err != nil {
			fmt.Fprintf(stderr, "depgraph-go-worker: restore working directory: %v\n", err)
		}
	}()

	if analysisUnit == nil {
		fmt.Fprintf(stderr, "depgraph-go-worker: safe static scan of %s\n", absRoot)
	} else {
		fmt.Fprintf(stderr, "depgraph-go-worker: analysis unit %s stage=%s root=%s starting\n", analysisUnit.UnitID, analysisUnit.Stage, analysisUnit.UnitRoot)
	}
	var result worker.Result
	if analysisUnit != nil {
		// The scan-scoped Go build cache is a process input from the core; it
		// is validated by the loader (absolute, outside the scan root) and
		// only consulted by package-scoped typed/semantic requests.
		options := worker.AnalysisUnitScanOptions{BuildCacheDir: os.Getenv("DEPGRAPH_GO_BUILD_CACHE")}
		result, err = worker.ScanWithAnalysisUnitOptions(absRoot, inventoryPath, *analysisUnit, options, func(phase, status string, items int) {
			fmt.Fprintf(stderr, "depgraph-progress phase=%s status=%s items=%d\n", phase, status, items)
		})
	} else if inventoryPath == "" {
		result, err = worker.Scan(absRoot)
	} else {
		result, err = worker.ScanWithInventory(absRoot, inventoryPath)
	}
	if err != nil {
		fmt.Fprintf(stderr, "depgraph-go-worker: %v\n", err)
		if emitErr := worker.EmitFailure(stdout, *scanID, absRoot, err); emitErr != nil {
			fmt.Fprintf(stderr, "depgraph-go-worker: emit failure: %v\n", emitErr)
		}
		return 3
	}
	if err := worker.Emit(stdout, *scanID, result); err != nil {
		fmt.Fprintf(stderr, "depgraph-go-worker: %v\n", err)
		return 3
	}
	if analysisUnit == nil {
		fmt.Fprintf(stderr, "depgraph-go-worker: analyzed %d files and emitted %d dependency sites\n", result.Coverage.FilesAnalyzed, result.Coverage.DependencySites)
	} else {
		fmt.Fprintf(stderr, "depgraph-go-worker: analysis unit %s stage=%s progress=completed items=%d files=%d sites=%d\n", analysisUnit.UnitID, analysisUnit.Stage, result.Coverage.FilesAnalyzed, result.Coverage.FilesAnalyzed, result.Coverage.DependencySites)
	}
	return 0
}
