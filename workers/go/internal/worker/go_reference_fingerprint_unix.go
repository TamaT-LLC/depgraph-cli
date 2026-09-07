//go:build unix

package worker

import (
	"os"
	"syscall"
)

// openReferenceFile opens a previously confined path without following a
// symlink that replaced the final component between the confinement check
// and this open.
func openReferenceFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
