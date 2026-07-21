package worker

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestDependencySnapshotIsIndependentOfModuleCacheLocation(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	module := Module{
		Dir: root, RelativeDir: ".", Path: "example.com/app",
		Requirements: []Requirement{{Path: "example.com/dep", Version: "v1.2.3"}},
	}

	build := func(cacheRoot string) goDependencySnapshot {
		dependencyRoot := filepath.Join(cacheRoot, "example.com", "dep@v1.2.3")
		dependencyFile := filepath.Join(dependencyRoot, "dep.go")
		writeTestFile(t, dependencyFile, "package dep\n\nfunc Value() int { return 1 }\n")
		builder := newGoDependencySnapshotBuilder(root, []Module{module}, WorkFile{})
		builder.setModuleCache(cacheRoot)
		reasons := builder.observeModuleLoad(module, []*packages.Package{{
			ID: "example.com/dep", PkgPath: "example.com/dep", GoFiles: []string{dependencyFile},
			CompiledGoFiles: []string{dependencyFile},
			Module: &packages.Module{
				Path: "example.com/dep", Version: "v1.2.3", Dir: dependencyRoot,
			},
		}})
		if len(reasons) != 0 {
			t.Fatalf("snapshot reasons = %v", reasons)
		}
		return builder.finalize("loaded")
	}

	first := build(canonicalTestRoot(t, t.TempDir()))
	second := build(canonicalTestRoot(t, t.TempDir()))
	if first.Status != "complete" || first.Fingerprint != second.Fingerprint {
		t.Fatalf("equivalent cache snapshots differ: first=%+v second=%+v", first, second)
	}
	if first.ModuleCount != 1 || first.PackageCount != 1 || first.FileCount != 1 {
		t.Fatalf("unexpected snapshot counts: %+v", first)
	}
}

func TestDependencySnapshotContentAndAvailabilityChangeProfileIdentity(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	cacheRoot := canonicalTestRoot(t, t.TempDir())
	dependencyRoot := filepath.Join(cacheRoot, "example.com", "dep@v1.2.3")
	dependencyFile := filepath.Join(dependencyRoot, "dep.go")
	module := Module{
		Dir: root, RelativeDir: ".", Path: "example.com/app",
		Requirements: []Requirement{{Path: "example.com/dep", Version: "v1.2.3"}},
	}

	build := func(contents, admittedCache string) goDependencySnapshot {
		writeTestFile(t, dependencyFile, contents)
		builder := newGoDependencySnapshotBuilder(root, []Module{module}, WorkFile{})
		builder.setModuleCache(admittedCache)
		builder.observeModuleLoad(module, []*packages.Package{{
			ID: "example.com/dep", PkgPath: "example.com/dep", GoFiles: []string{dependencyFile},
			Module: &packages.Module{Path: "example.com/dep", Version: "v1.2.3", Dir: dependencyRoot},
		}})
		return builder.finalize("loaded")
	}

	first := build("package dep\nconst Value = 1\n", cacheRoot)
	changed := build("package dep\nconst Value = 2\n", cacheRoot)
	unavailable := build("package dep\nconst Value = 2\n", canonicalTestRoot(t, t.TempDir()))
	if first.Fingerprint == changed.Fingerprint || changed.Fingerprint == unavailable.Fingerprint {
		t.Fatalf("content/availability change did not invalidate snapshot: first=%+v changed=%+v unavailable=%+v", first, changed, unavailable)
	}
	if unavailable.Status != "partial" || !slices.Contains(unavailable.Reasons, "dependency-source-outside-admitted-roots") {
		t.Fatalf("unavailable snapshot outcome = %+v", unavailable)
	}
	firstProfile := goProfileID("linux", "amd64", "0", nil, "rta-cha", first.Status, first.Fingerprint)
	changedProfile := goProfileID("linux", "amd64", "0", nil, "rta-cha", changed.Status, changed.Fingerprint)
	unavailableProfile := goProfileID("linux", "amd64", "0", nil, "rta-cha", unavailable.Status, unavailable.Fingerprint)
	if firstProfile == changedProfile || changedProfile == unavailableProfile {
		t.Fatalf("dependency snapshot did not affect profile identity: %s %s %s", firstProfile, changedProfile, unavailableProfile)
	}
}

func TestDependencySnapshotCanonicalizesChecksumVendorAndReplaceInputs(t *testing.T) {
	build := func(root, sums, vendor, replacementVersion string) goDependencySnapshot {
		writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/app\n")
		writeTestFile(t, filepath.Join(root, "go.sum"), sums)
		writeTestFile(t, filepath.Join(root, "vendor", "modules.txt"), vendor)
		module := Module{
			Dir: root, RelativeDir: ".", Path: "example.com/app", ManifestPath: filepath.Join(root, "go.mod"),
			Requirements: []Requirement{{Path: "example.com/dep", Version: "v1.2.3"}},
			Replacements: []Replacement{{
				OldPath: "example.com/dep", OldVersion: "v1.2.3",
				NewPath: "example.com/replaced", NewVersion: replacementVersion,
			}},
		}
		return newGoDependencySnapshotBuilder(root, []Module{module}, WorkFile{}).finalize("loaded")
	}

	first := build(
		canonicalTestRoot(t, t.TempDir()),
		"example.com/dep v1.2.3 h1:source\nexample.com/dep v1.2.3/go.mod h1:manifest\n",
		"# example.com/dep v1.2.3\n## explicit\nexample.com/dep\n",
		"v2.0.0",
	)
	reordered := build(
		canonicalTestRoot(t, t.TempDir()),
		"example.com/dep v1.2.3/go.mod h1:manifest\nexample.com/dep v1.2.3 h1:source\n",
		"# example.com/dep v1.2.3\n## explicit\nexample.com/dep\n",
		"v2.0.0",
	)
	checksumChanged := build(
		canonicalTestRoot(t, t.TempDir()),
		"example.com/dep v1.2.3 h1:changed\nexample.com/dep v1.2.3/go.mod h1:manifest\n",
		"# example.com/dep v1.2.3\n## explicit\nexample.com/dep\n",
		"v2.0.0",
	)
	vendorChanged := build(
		canonicalTestRoot(t, t.TempDir()),
		"example.com/dep v1.2.3 h1:source\nexample.com/dep v1.2.3/go.mod h1:manifest\n",
		"# example.com/dep v1.2.4\n## explicit\nexample.com/dep\n",
		"v2.0.0",
	)
	replacementChanged := build(
		canonicalTestRoot(t, t.TempDir()),
		"example.com/dep v1.2.3 h1:source\nexample.com/dep v1.2.3/go.mod h1:manifest\n",
		"# example.com/dep v1.2.3\n## explicit\nexample.com/dep\n",
		"v2.1.0",
	)
	if first.Fingerprint != reordered.Fingerprint {
		t.Fatalf("checksum declaration order changed fingerprint: first=%+v reordered=%+v", first, reordered)
	}
	for name, snapshot := range map[string]goDependencySnapshot{
		"checksum": checksumChanged, "vendor": vendorChanged, "replacement": replacementChanged,
	} {
		if first.Fingerprint == snapshot.Fingerprint {
			t.Fatalf("%s input change did not invalidate fingerprint: first=%+v changed=%+v", name, first, snapshot)
		}
	}
}

func TestDependencySnapshotRejectsSymlinkedSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not consistently available on Windows")
	}
	root := canonicalTestRoot(t, t.TempDir())
	cacheRoot := canonicalTestRoot(t, t.TempDir())
	dependencyRoot := filepath.Join(cacheRoot, "example.com", "dep@v1.0.0")
	realFile := filepath.Join(dependencyRoot, "real.go")
	linkedFile := filepath.Join(dependencyRoot, "linked.go")
	writeTestFile(t, realFile, "package dep\n")
	if err := os.Symlink(realFile, linkedFile); err != nil {
		t.Fatal(err)
	}
	module := Module{Dir: root, RelativeDir: ".", Path: "example.com/app"}
	builder := newGoDependencySnapshotBuilder(root, []Module{module}, WorkFile{})
	builder.setModuleCache(cacheRoot)
	reasons := builder.observeModuleLoad(module, []*packages.Package{{
		ID: "example.com/dep", PkgPath: "example.com/dep", GoFiles: []string{linkedFile},
		Module: &packages.Module{Path: "example.com/dep", Version: "v1.0.0", Dir: dependencyRoot},
	}})
	if !slices.Contains(reasons, "dependency-source-symlink") {
		t.Fatalf("symlinked dependency reasons = %v", reasons)
	}
}

func TestScanFingerprintsLocalDependencySnapshotWithoutLeakingRoot(t *testing.T) {
	source := filepath.Join("testdata", "dependency_snapshot")
	firstRoot := filepath.Join(t.TempDir(), "checkout-a")
	secondRoot := filepath.Join(t.TempDir(), "unrelated", "checkout-b")
	copyTree(t, source, firstRoot)
	copyTree(t, source, secondRoot)

	first, err := Scan(firstRoot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Scan(secondRoot)
	if err != nil {
		t.Fatal(err)
	}
	firstFingerprint := first.Profile.Properties["go_dependency_snapshot_fingerprint"]
	if first.Profile.Properties["go_dependency_snapshot_status"] != "complete" || firstFingerprint == "" {
		t.Fatalf("first dependency snapshot = %+v; diagnostics=%+v", first.Profile.Properties, first.Diagnostics)
	}
	if first.Profile.ID != second.Profile.ID || firstFingerprint != second.Profile.Properties["go_dependency_snapshot_fingerprint"] {
		t.Fatalf("checkout location changed dependency identity: first=%+v second=%+v", first.Profile, second.Profile)
	}

	writeTestFile(t, filepath.Join(secondRoot, "dep", "value.go"), "package dep\n\nfunc Value() string { return \"changed\" }\n")
	changed, err := Scan(secondRoot)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Profile.ID == first.Profile.ID || changed.Profile.Properties["go_dependency_snapshot_fingerprint"] == firstFingerprint {
		t.Fatalf("dependency source change retained identity: first=%+v changed=%+v", first.Profile, changed.Profile)
	}
	for _, result := range []Result{first, second, changed} {
		encoded, encodeErr := canonicalJSON(result.Profile)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		if strings.Contains(string(encoded), firstRoot) || strings.Contains(string(encoded), secondRoot) {
			t.Fatalf("profile leaked a checkout path: %s", encoded)
		}
	}
}
