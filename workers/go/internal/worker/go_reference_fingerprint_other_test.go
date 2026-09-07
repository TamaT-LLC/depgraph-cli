//go:build !unix && !windows

package worker

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestOpenReferenceFileFailsClosedWithoutNoFollow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "real.go")
	writeTestFile(t, path, "package p\n")
	file, err := openReferenceFile(path)
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, errReferenceOpenNoFollowUnavailable) {
		t.Fatalf("openReferenceFile = (%v, %v)", file, err)
	}
	if _, ok := goReferenceFileDigest(path); ok {
		t.Fatal("digest succeeded without a no-follow open")
	}
}
