package worker

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

const repositoryInventoryContractVersion = "depgraph-repository-file-inventory-v1"
const maxRepositoryInventoryBytes = 64 * 1024 * 1024
const maxRepositoryInventoryFiles = 1_000_000

type repositoryInventoryDocument struct {
	ContractVersion string   `json:"contract_version"`
	Paths           []string `json:"paths"`
}

type repositoryInventory struct {
	paths []string
}

type repositoryFileEntry struct {
	path  string
	entry fs.DirEntry
}

func readRepositoryInventory(file string) (*repositoryInventory, error) {
	info, err := os.Stat(file)
	if err != nil {
		return nil, fmt.Errorf("read repository inventory: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxRepositoryInventoryBytes {
		return nil, fmt.Errorf("repository inventory file exceeds its closed byte limit")
	}
	handle, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("open repository inventory: %w", err)
	}
	defer handle.Close()
	decoder := json.NewDecoder(io.LimitReader(handle, maxRepositoryInventoryBytes+1))
	decoder.DisallowUnknownFields()
	var document repositoryInventoryDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode repository inventory: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("repository inventory contains trailing data")
	}
	if document.ContractVersion != repositoryInventoryContractVersion {
		return nil, fmt.Errorf("repository inventory contract version is unsupported")
	}
	if len(document.Paths) > maxRepositoryInventoryFiles {
		return nil, fmt.Errorf("repository inventory exceeds its closed file-count limit")
	}
	seen := make(map[string]struct{}, len(document.Paths))
	for _, relative := range document.Paths {
		if !fs.ValidPath(relative) || relative == "." || path.Clean(relative) != relative ||
			strings.Contains(relative, "\\") || strings.IndexFunc(relative, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("repository inventory contains a non-canonical path")
		}
		for _, component := range strings.Split(relative, "/") {
			if shouldSkipInventoryDirectory(component) {
				return nil, fmt.Errorf("repository inventory contains a generated directory")
			}
		}
		if _, duplicate := seen[relative]; duplicate {
			return nil, fmt.Errorf("repository inventory contains a duplicate path")
		}
		seen[relative] = struct{}{}
	}
	paths := append([]string(nil), document.Paths...)
	sort.Strings(paths)
	return &repositoryInventory{paths: paths}, nil
}

func shouldSkipInventoryDirectory(name string) bool {
	switch name {
	case ".astro", ".cache", ".depgraph", ".git", ".hg", ".next", ".output", ".svn", ".turbo",
		"node_modules", "target":
		return true
	default:
		return false
	}
}

func repositoryFileEntries(root string, inventory *repositoryInventory) ([]repositoryFileEntry, error) {
	if inventory != nil {
		entries := make([]repositoryFileEntry, 0, len(inventory.paths))
		for _, relative := range inventory.paths {
			absolute := filepath.Join(root, filepath.FromSlash(relative))
			info, err := os.Lstat(absolute)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("inspect repository inventory path %s: %w", relative, err)
			}
			if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
				continue
			}
			entries = append(entries, repositoryFileEntry{
				path:  absolute,
				entry: fs.FileInfoToDirEntry(info),
			})
		}
		return entries, nil
	}

	var entries []repositoryFileEntry
	err := filepath.WalkDir(root, func(candidate string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && candidate != root && shouldSkipDirectory(entry.Name()) {
			return filepath.SkipDir
		}
		if !entry.IsDir() {
			entries = append(entries, repositoryFileEntry{path: candidate, entry: entry})
		}
		return nil
	})
	return entries, err
}
