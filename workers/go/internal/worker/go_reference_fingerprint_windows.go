//go:build windows

package worker

import (
	"os"
	"syscall"
)

// openReferenceFile opens a previously confined path without following a
// reparse point that replaced the final component between the confinement
// check and this open. FILE_FLAG_OPEN_REPARSE_POINT is atomic for that last
// component; Stat on the returned handle then rejects a non-regular file.
func openReferenceFile(path string) (*os.File, error) {
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(
		pathp,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}
