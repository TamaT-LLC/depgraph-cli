//go:build linux

package worker

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openReferenceFile opens a confined path from a trusted root descriptor.
// Every intermediate directory and the final component are opened with
// openat(2) and O_NOFOLLOW so a swapped parent symlink cannot escape the
// scan root.
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
	dirfd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			_ = syscall.Close(dirfd)
		}
	}()
	for index, name := range components {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		if index < len(components)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(dirfd, name, flags, 0)
		if err != nil {
			return nil, err
		}
		_ = syscall.Close(dirfd)
		dirfd = next
		if index == len(components)-1 {
			owned = false
			return os.NewFile(uintptr(next), path), nil
		}
	}
	return nil, os.ErrInvalid
}
