package worker

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
