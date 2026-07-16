package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	version := flags.Bool("version", false, "print worker version")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: depgraph-go-worker --root <path> --scan-id <id>")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *version {
		fmt.Fprintf(stdout, "depgraph-go-worker %s (protocol %s)\n", worker.AdapterVersion, worker.ProtocolVersion)
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

	fmt.Fprintf(stderr, "depgraph-go-worker: safe static scan of %s\n", absRoot)
	result, err := worker.Scan(absRoot)
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
	fmt.Fprintf(stderr, "depgraph-go-worker: analyzed %d files and emitted %d dependency sites\n", result.Coverage.FilesAnalyzed, result.Coverage.DependencySites)
	return 0
}
