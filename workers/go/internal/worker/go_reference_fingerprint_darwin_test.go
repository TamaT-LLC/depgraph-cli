//go:build darwin

package worker

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Darwin APFS lookups are often case-insensitive. The walk still opens each
// listing component with O_NOFOLLOW so a same-case symlink cannot escape.
func TestOpenReferenceFileRejectsCasePreservingSymlinkOnDarwin(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	realDir := filepath.Join(root, "pkg")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(realDir, "dep.go")
	writeTestFile(t, realFile, "package dep\n")
	outside := t.TempDir()
	writeTestFile(t, filepath.Join(outside, "dep.go"), "package leaked\n")
	alias := filepath.Join(root, "Pkg")
	if _, err := os.Lstat(alias); err == nil {
		t.Skip("filesystem treats Pkg and pkg as the same name")
	}
	if err := os.Symlink(outside, alias); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	escaped := filepath.Join(alias, "dep.go")
	file, err := openReferenceFile(root, escaped)
	if file != nil {
		_ = file.Close()
		t.Fatal("darwin walk followed a case-variant symlink")
	}
	if err == nil || errors.Is(err, errReferenceOpenNoFollowUnavailable) {
		t.Fatalf("darwin case-variant symlink = %v", err)
	}
}
