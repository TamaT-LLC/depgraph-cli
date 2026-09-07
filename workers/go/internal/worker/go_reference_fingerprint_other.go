//go:build !unix && !windows

package worker

import "os"

// openReferenceFile refuses to hash on platforms that cannot open the final
// path component without following a symlink. Lstat-then-Open would race with
// a swap of that component, so those targets fail closed instead.
func openReferenceFile(string) (*os.File, error) {
	return nil, errReferenceOpenNoFollowUnavailable
}
