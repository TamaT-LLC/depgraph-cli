//go:build !linux && !darwin

package worker

import "os"

// openReferenceFile refuses to hash unless every path component can be opened
// without following a symlink or reparse point. Linux and macOS use openat(2) with
// O_NOFOLLOW; other targets lack that primitive in this package, so they fail
// closed instead of racing a string-path open.
func openReferenceFile(string, string) (*os.File, error) {
	return nil, errReferenceOpenNoFollowUnavailable
}
