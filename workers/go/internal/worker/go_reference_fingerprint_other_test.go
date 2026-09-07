//go:build !linux && !darwin

package worker

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
)

func TestOpenReferenceFileFailsClosedWithoutNoFollow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "real.go")
	writeTestFile(t, path, "package p\n")
	file, err := openReferenceFile(filepath.Dir(path), path)
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, errReferenceOpenNoFollowUnavailable) {
		t.Fatalf("openReferenceFile = (%v, %v)", file, err)
	}
	if _, ok := goReferenceFileDigest(filepath.Dir(path), path); ok {
		t.Fatal("digest succeeded without a no-follow open")
	}
}

func TestComputeGoReferenceFingerprintOmitsDigestWithoutNoFollow(t *testing.T) {
	fp := referenceFingerprintWithInRepoDep(t)
	if fp.Fingerprint != "" {
		t.Fatalf("content-less fingerprint = %q", fp.Fingerprint)
	}
	if !slices.Contains(fp.Reasons, "reference-file-nofollow-unavailable") {
		t.Fatalf("reasons = %v", fp.Reasons)
	}
	properties := goLoaderProperties(&goLoaderReport{ReferenceFingerprint: fp})
	if _, ok := properties["go_reference_fingerprint"]; ok {
		t.Fatal("empty fingerprint leaked into loader properties")
	}
}
