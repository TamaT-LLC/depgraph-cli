package worker

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/tools/go/packages"
)

func referenceFingerprintWithInRepoDep(t *testing.T) goReferenceFingerprint {
	t.Helper()
	root := canonicalTestRoot(t, t.TempDir())
	depFile := filepath.Join(root, "dep.go")
	writeTestFile(t, depFile, "package dep\n")
	module := Module{Dir: root, RelativeDir: ".", Path: "example.com/app"}
	dep := &packages.Package{
		ID: "example.com/app/dep", PkgPath: "example.com/app/dep", Name: "dep",
		Module:  &packages.Module{Path: "example.com/app", Dir: root},
		GoFiles: []string{depFile}, CompiledGoFiles: []string{depFile},
	}
	target := &packages.Package{
		ID: "example.com/app", PkgPath: "example.com/app", Name: "app",
		Module:  &packages.Module{Path: "example.com/app", Dir: root},
		Imports: map[string]*packages.Package{"example.com/app/dep": dep},
	}
	return computeGoReferenceFingerprint(root, []Module{module}, []*packages.Package{target}, nil)
}

func TestSupportedUnixMustGenerateReferenceFingerprint(t *testing.T) {
	supported := runtime.GOOS == "linux" || runtime.GOOS == "darwin"
	if referenceOpenNoFollowAvailable() != supported {
		t.Fatalf("GOOS=%s: no-follow available=%v, want %v", runtime.GOOS, referenceOpenNoFollowAvailable(), supported)
	}
	if !supported {
		return
	}
	fp := referenceFingerprintWithInRepoDep(t)
	if fp.Fingerprint == "" || fp.PackageCount != 1 || fp.FileCount != 1 {
		t.Fatalf("supported GOOS %s omitted a reference fingerprint: %+v", runtime.GOOS, fp)
	}
	if slices.Contains(fp.Reasons, "reference-file-nofollow-unavailable") {
		t.Fatalf("supported GOOS %s reported nofollow unavailable: %v", runtime.GOOS, fp.Reasons)
	}
	properties := goLoaderProperties(&goLoaderReport{ReferenceFingerprint: fp})
	if properties["go_reference_fingerprint"] != fp.Fingerprint {
		t.Fatalf("loader properties omitted the fingerprint: %v", properties)
	}
}

func TestOpenReferenceFileOpensRegularFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "real.go")
	writeTestFile(t, path, "package p\n")
	file, err := openReferenceFile(root, path)
	if errors.Is(err, errReferenceOpenNoFollowUnavailable) {
		t.Skip("no-follow open is unavailable on this platform")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("opened mode = %s", info.Mode())
	}
}

func TestOpenReferenceFileRejectsFinalComponentSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.go")
	writeTestFile(t, target, "package p\n")
	link := filepath.Join(dir, "link.go")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	file, err := openReferenceFile(dir, link)
	if file != nil {
		_ = file.Close()
		t.Fatal("expected symlink open to fail")
	}
	if err == nil {
		t.Fatal("expected symlink open to fail")
	}
	if _, ok := goReferenceFileDigest(dir, link); ok {
		t.Fatal("digest followed a final-component symlink")
	}
}

func TestOpenReferenceFileRejectsParentDirectorySymlinkSwap(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	parent := filepath.Join(root, "pkg")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(parent, "dep.go")
	writeTestFile(t, inside, "package dep\n")
	if _, err := openReferenceFile(root, inside); errors.Is(err, errReferenceOpenNoFollowUnavailable) {
		t.Skip("no-follow open is unavailable on this platform")
	}
	confined, ok := confinedMetadataFile(root, inside)
	if !ok {
		t.Fatal("confinement failed")
	}
	outsideDir := t.TempDir()
	writeTestFile(t, filepath.Join(outsideDir, "dep.go"), "package leaked\nconst Secret = true\n")
	if err := os.Rename(parent, parent+".orig"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, parent); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	file, err := openReferenceFile(root, confined)
	if file != nil {
		_ = file.Close()
		t.Fatal("parent symlink swap was followed")
	}
	if err == nil {
		t.Fatal("parent symlink swap was followed")
	}
	if _, ok := goReferenceFileDigest(root, confined); ok {
		t.Fatal("digest followed a swapped parent directory")
	}
}

func TestOpenReferenceFileRejectsRootSymlinkSwap(t *testing.T) {
	parent := canonicalTestRoot(t, t.TempDir())
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "dep.go")
	writeTestFile(t, inside, "package dep\n")
	if _, err := openReferenceFile(root, inside); errors.Is(err, errReferenceOpenNoFollowUnavailable) {
		t.Skip("no-follow open is unavailable on this platform")
	}
	confined, ok := confinedMetadataFile(root, inside)
	if !ok {
		t.Fatal("confinement failed")
	}
	outside := t.TempDir()
	writeTestFile(t, filepath.Join(outside, "dep.go"), "package leaked\nconst Secret = true\n")
	if err := os.Rename(root, root+".orig"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	file, err := openReferenceFile(root, confined)
	if file != nil {
		_ = file.Close()
		t.Fatal("root symlink swap was followed")
	}
	if err == nil {
		t.Fatal("root symlink swap was followed")
	}
	if _, ok := goReferenceFileDigest(root, confined); ok {
		t.Fatal("digest followed a swapped scan root")
	}
}

func TestGoReferenceFileDigestHashesOpenedHandle(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "real.go")
	writeTestFile(t, path, "package p\n")
	digest, ok := goReferenceFileDigest(root, path)
	if !ok {
		if _, err := openReferenceFile(root, path); errors.Is(err, errReferenceOpenNoFollowUnavailable) {
			t.Skip("no-follow open is unavailable on this platform")
		}
		t.Fatal("digest missing for a regular file")
	}
	if digest == "" {
		t.Fatal("empty digest")
	}
}

func TestComputeGoReferenceFingerprintBindsFileContentWhenNoFollowAvailable(t *testing.T) {
	fp := referenceFingerprintWithInRepoDep(t)
	if fp.Fingerprint == "" {
		if slices.Contains(fp.Reasons, "reference-file-nofollow-unavailable") {
			t.Skip("no-follow open is unavailable on this platform")
		}
		t.Fatalf("fingerprint missing: %+v", fp)
	}
	if fp.PackageCount != 1 || fp.FileCount != 1 {
		t.Fatalf("fingerprint = %+v", fp)
	}
}

func TestComputeGoReferenceFingerprintOmitsDigestWhenAFileIsUnreadable(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	depFile := filepath.Join(root, "dep.go")
	writeTestFile(t, depFile, "package dep\n")
	if err := os.Chmod(depFile, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(depFile, 0o644) })
	module := Module{Dir: root, RelativeDir: ".", Path: "example.com/app"}
	dep := &packages.Package{
		ID: "example.com/app/dep", PkgPath: "example.com/app/dep", Name: "dep",
		Module:  &packages.Module{Path: "example.com/app", Dir: root},
		GoFiles: []string{depFile}, CompiledGoFiles: []string{depFile},
	}
	target := &packages.Package{
		ID: "example.com/app", PkgPath: "example.com/app", Name: "app",
		Module:  &packages.Module{Path: "example.com/app", Dir: root},
		Imports: map[string]*packages.Package{"example.com/app/dep": dep},
	}
	fp := computeGoReferenceFingerprint(root, []Module{module}, []*packages.Package{target}, nil)
	if fp.Fingerprint != "" {
		t.Fatalf("incomplete fingerprint = %q reasons=%v", fp.Fingerprint, fp.Reasons)
	}
	if !slices.Contains(fp.Reasons, "reference-file-unreadable") && !slices.Contains(fp.Reasons, "reference-file-nofollow-unavailable") {
		t.Fatalf("reasons = %v", fp.Reasons)
	}
}
