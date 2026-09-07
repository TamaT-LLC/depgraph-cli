package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sort"

	"golang.org/x/tools/go/packages"
)

const goReferenceFingerprintSchema = "go-reference-fingerprint-v1"

// goReferenceFingerprint digests the source of every in-repo package in the
// transitive import closure of a unit's target packages. It complements the
// module-wide dependency snapshot: the snapshot covers external modules and is
// shared by every chunk of a module, while this fingerprint changes only when
// an in-repo dependency of this particular chunk changes.
type goReferenceFingerprint struct {
	Fingerprint  string
	PackageCount int
	FileCount    int
	Reasons      []string
}

type goReferenceFingerprintFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type goReferenceFingerprintPackage struct {
	Module  string                       `json:"module"`
	ID      string                       `json:"id"`
	PkgPath string                       `json:"pkg_path"`
	ForTest string                       `json:"for_test,omitempty"`
	Files   []goReferenceFingerprintFile `json:"files"`
}

// computeGoReferenceFingerprint walks the metadata listing from the target
// variants through in-repo imports only. External and standard-library
// packages terminate the walk because the dependency snapshot already
// witnesses them. digests caches file digests across calls in one session.
func computeGoReferenceFingerprint(root string, modules []Module, targets []*packages.Package, digests map[string]string) goReferenceFingerprint {
	if digests == nil {
		digests = map[string]string{}
	}
	targetIDs := map[string]bool{}
	for _, target := range targets {
		if target != nil {
			targetIDs[target.ID] = true
		}
	}
	visited := map[string]bool{}
	reasons := map[string]bool{}
	var entries []goReferenceFingerprintPackage
	queue := append([]*packages.Package(nil), targets...)
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if pkg == nil || visited[pkg.ID] {
			continue
		}
		visited[pkg.ID] = true
		if !targetIDs[pkg.ID] {
			origin, module := goLoaderClassifyPackage(root, modules, pkg)
			if origin != goLoaderOriginInRepo {
				continue
			}
			entry := goReferenceFingerprintPackage{
				Module: cleanSlash(module.RelativeDir), ID: pkg.ID, PkgPath: pkg.PkgPath, ForTest: pkg.ForTest,
				Files: []goReferenceFingerprintFile{},
			}
			for _, file := range dependencySnapshotPackageFiles(pkg) {
				confined, ok := confinedMetadataFile(root, file)
				if !ok {
					reasons["reference-file-outside-root"] = true
					continue
				}
				digest, ok := digests[confined]
				if !ok {
					digest, ok = goReferenceFileDigest(confined)
					if !ok {
						reasons["reference-file-unreadable"] = true
						continue
					}
					digests[confined] = digest
				}
				entry.Files = append(entry.Files, goReferenceFingerprintFile{Path: relativePath(root, confined), Digest: digest})
			}
			sort.SliceStable(entry.Files, func(left, right int) bool { return entry.Files[left].Path < entry.Files[right].Path })
			entries = append(entries, entry)
		}
		importPaths := make([]string, 0, len(pkg.Imports))
		for importPath := range pkg.Imports {
			importPaths = append(importPaths, importPath)
		}
		sort.Strings(importPaths)
		for _, importPath := range importPaths {
			if imported := pkg.Imports[importPath]; imported != nil {
				queue = append(queue, imported)
			}
		}
	}
	sort.SliceStable(entries, func(left, right int) bool {
		if entries[left].Module != entries[right].Module {
			return entries[left].Module < entries[right].Module
		}
		return entries[left].ID < entries[right].ID
	})
	if entries == nil {
		entries = []goReferenceFingerprintPackage{}
	}
	reasonList := make([]string, 0, len(reasons))
	for reason := range reasons {
		reasonList = append(reasonList, reason)
	}
	sort.Strings(reasonList)
	fileCount := 0
	for _, entry := range entries {
		fileCount += len(entry.Files)
	}
	payload := map[string]any{"schema": goReferenceFingerprintSchema, "packages": entries, "reasons": reasonList}
	return goReferenceFingerprint{
		Fingerprint:  stableIDFromValue("go_reference_fingerprint", payload),
		PackageCount: len(entries), FileCount: fileCount, Reasons: reasonList,
	}
}

func goReferenceFileDigest(path string) (string, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", false
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), true
}
