//go:build linux || darwin

package worker

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openReferenceFile opens a confined path from a trusted root descriptor.
// The root and every subsequent component are opened with O_NOFOLLOW so a
// swapped scan-root or parent symlink cannot escape the scan root.
func openReferenceFile(root, path string) (*os.File, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	if rel == "." || !filepath.IsLocal(rel) {
		return nil, os.ErrInvalid
	}
	var components []string
	for _, name := range strings.Split(filepath.ToSlash(rel), "/") {
		if name == "" || name == "." {
			continue
		}
		if name == ".." {
			return nil, os.ErrInvalid
		}
		components = append(components, name)
	}
	if len(components) == 0 {
		return nil, os.ErrInvalid
	}
	dirfd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			_ = unix.Close(dirfd)
		}
	}()
	for index, name := range components {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if index < len(components)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(dirfd, name, flags, 0)
		if err != nil {
			return nil, err
		}
		_ = unix.Close(dirfd)
		dirfd = next
		if index == len(components)-1 {
			owned = false
			return os.NewFile(uintptr(next), path), nil
		}
	}
	return nil, os.ErrInvalid
}
