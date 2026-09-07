package worker

import (
	"errors"
	"os"
	"path/filepath"
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

func TestOpenReferenceFileOpensRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "real.go")
	writeTestFile(t, path, "package p\n")
	file, err := openReferenceFile(path)
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
	file, err := openReferenceFile(link)
	if file != nil {
		_ = file.Close()
		t.Fatal("expected symlink open to fail")
	}
	if err == nil {
		t.Fatal("expected symlink open to fail")
	}
	if _, ok := goReferenceFileDigest(link); ok {
		t.Fatal("digest followed a final-component symlink")
	}
}

func TestGoReferenceFileDigestHashesOpenedHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "real.go")
	writeTestFile(t, path, "package p\n")
	digest, ok := goReferenceFileDigest(path)
	if !ok {
		if _, err := openReferenceFile(path); errors.Is(err, errReferenceOpenNoFollowUnavailable) {
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
