//go:build linux || darwin

package worker

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// These cases compile on Darwin even when the no-follow walk is missing, so a
// stub that returns errReferenceOpenNoFollowUnavailable fails them. Linux
// executes the same walk Darwin ships.

func TestOpenReferenceFileMustHashRegularFilesOnLinuxAndDarwin(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	path := filepath.Join(root, "real.go")
	writeTestFile(t, path, "package p\n")
	file, err := openReferenceFile(root, path)
	if errors.Is(err, errReferenceOpenNoFollowUnavailable) {
		t.Fatal("linux and darwin must open confined files with openat(O_NOFOLLOW)")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest, ok := goReferenceFileDigest(root, path)
	if !ok || digest == "" {
		t.Fatalf("digest = %q ok=%v", digest, ok)
	}
	fp := referenceFingerprintWithInRepoDep(t)
	if fp.Fingerprint == "" || fp.PackageCount != 1 || fp.FileCount != 1 {
		t.Fatalf("fingerprint = %+v", fp)
	}
	if slices.Contains(fp.Reasons, "reference-file-nofollow-unavailable") {
		t.Fatalf("reasons = %v", fp.Reasons)
	}
}

func TestOpenReferenceFileMustRejectSymlinkSwapOnLinuxAndDarwin(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	parent := filepath.Join(root, "pkg")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(parent, "dep.go")
	writeTestFile(t, inside, "package dep\n")
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
	if err == nil || errors.Is(err, errReferenceOpenNoFollowUnavailable) {
		t.Fatalf("parent symlink swap = %v", err)
	}
	if _, ok := goReferenceFileDigest(root, confined); ok {
		t.Fatal("digest followed a swapped parent directory")
	}
}
