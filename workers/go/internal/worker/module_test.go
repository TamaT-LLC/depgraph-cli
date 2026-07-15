package worker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGoModBlocksAndReplace(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "go.mod")
	content := `module "example.com/quoted"

go 1.24
toolchain go1.24.3

require ( // dependencies
  example.com/a v1.2.3
  example.com/b v2.0.0 // indirect
) // requirements
replace ( // replacements
  example.com/a v1.2.3 => ../a
  example.com/b => example.com/fork/b v2.1.0
) // replacements
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	module, diagnostics := parseGoMod(path, root)
	if len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diagnostics)
	}
	if module.Path != "example.com/quoted" || module.GoVersion != "1.24" || module.Toolchain != "go1.24.3" {
		t.Fatalf("unexpected module: %+v", module)
	}
	if len(module.Requirements) != 2 || !module.Requirements[1].Indirect {
		t.Fatalf("unexpected requirements: %+v", module.Requirements)
	}
	if len(module.Replacements) != 2 || module.Replacements[0].NewPath != "../a" || module.Replacements[1].NewVersion != "v2.1.0" {
		t.Fatalf("unexpected replacements: %+v", module.Replacements)
	}
}

func TestParseGoWorkUseBlock(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "go.work")
	content := `go 1.24
use ( // workspace members
  "./one"
  ./two // a comment
) // workspace members
replace example.com/a => ./one
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	work, diagnostics := parseGoWork(path, root)
	if len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diagnostics)
	}
	if len(work.Uses) != 2 || work.Uses[0] != "./one" || work.Uses[1] != "./two" {
		t.Fatalf("unexpected use directives: %+v", work.Uses)
	}
	if len(work.Replacements) != 1 || work.Replacements[0].NewPath != "./one" {
		t.Fatalf("unexpected replacement: %+v", work.Replacements)
	}
}

func TestParseGoModReportsEachMalformedOrUnsupportedEntryOnce(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "go.mod")
	content := `module example.com/app
go 1.26.1
require (
  example.com/kept v1.2.3
  example.com/missing-version
)
exclude (
  example.com/unsupported-one v1.0.0
  example.com/unsupported-two v2.0.0
)
tool (
)
requre example.com/typo v3.0.0
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	module, diagnostics := parseGoMod(path, root)
	if len(module.Requirements) != 1 || module.Requirements[0].Path != "example.com/kept" {
		t.Fatalf("valid requirement was not retained: %+v", module.Requirements)
	}
	if module.ParseIssues != 5 || len(diagnostics) != 5 {
		t.Fatalf("manifest issues were dropped or double-counted: issues=%d diagnostics=%+v", module.ParseIssues, diagnostics)
	}
	for _, diagnostic := range diagnostics {
		if len(diagnostic.Evidence) != 1 || diagnostic.Evidence[0].StartLine == 0 {
			t.Fatalf("manifest issue lacks source evidence: %+v", diagnostic)
		}
	}
}

func TestParseGoWorkReportsEachMalformedOrUnsupportedEntryOnce(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "go.work")
	content := `go 1.26.1
use (
  ./kept
)
godebug (
  default=go1.26
  panicnil=1
)
future (
)
ues ./typo
use
replace example.com/broken =>
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	work, diagnostics := parseGoWork(path, root)
	if len(work.Uses) != 1 || work.Uses[0] != "./kept" {
		t.Fatalf("valid workspace use was not retained: %+v", work.Uses)
	}
	if work.ParseIssues != 6 || len(diagnostics) != 6 {
		t.Fatalf("workspace issues were dropped or double-counted: issues=%d diagnostics=%+v", work.ParseIssues, diagnostics)
	}
}
