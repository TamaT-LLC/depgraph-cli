//go:build !unix

package worker

import "os"

// openReferenceFile refuses to hash unless the final path component can be
// opened without following a symlink or reparse point. CreateFile with
// FILE_FLAG_OPEN_REPARSE_POINT still follows intermediate reparse points, so
// Windows is fail-closed here along with every other non-Unix target.
func openReferenceFile(string) (*os.File, error) {
	return nil, errReferenceOpenNoFollowUnavailable
}
