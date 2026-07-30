package worker

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Requirement struct {
	Path     string
	Version  string
	Indirect bool
	Line     int
}

type Replacement struct {
	OldPath    string
	OldVersion string
	NewPath    string
	NewVersion string
	Line       int
}

type Module struct {
	Dir          string
	RelativeDir  string
	Path         string
	GoVersion    string
	Toolchain    string
	Requirements []Requirement
	Replacements []Replacement
	ManifestPath string
	ParseIssues  int
}

type WorkFile struct {
	Path         string
	GoVersion    string
	Toolchain    string
	Uses         []string
	Replacements []Replacement
	ParseIssues  int
}

var errPathConfinement = errors.New("path is outside the canonical scan root")

func resolveRegularFileWithinRoot(root, candidate string) (string, error) {
	if _, err := os.Lstat(candidate); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	resolved = filepath.Clean(resolved)
	canonicalRoot := filepath.Clean(root)
	if !isWithinRoot(canonicalRoot, resolved) {
		// macOS commonly exposes /var through the /private/var symlink. Resolve the
		// root only on a lexical mismatch; Scan already supplies a canonical root,
		// so the hot source-file path does not pay for this extra filesystem call.
		if evaluatedRoot, rootErr := filepath.EvalSymlinks(canonicalRoot); rootErr == nil {
			canonicalRoot = filepath.Clean(evaluatedRoot)
		}
	}
	if !isWithinRoot(canonicalRoot, resolved) {
		return "", fmt.Errorf("%w: %q resolves to %q", errPathConfinement, candidate, resolved)
	}
	resolvedInfo, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if !resolvedInfo.Mode().IsRegular() {
		return "", fmt.Errorf("%q is not a regular file", candidate)
	}
	return resolved, nil
}

func openRegularFileWithinRoot(root, candidate string) (*os.File, error) {
	resolved, err := resolveRegularFileWithinRoot(root, candidate)
	if err != nil {
		return nil, err
	}
	return os.Open(resolved)
}

func readRegularFileWithinRoot(root, candidate string) ([]byte, error) {
	resolved, err := resolveRegularFileWithinRoot(root, candidate)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolved)
}

func parseGoMod(path, root string) (Module, []Diagnostic) {
	module := Module{Dir: filepath.Dir(path), ManifestPath: path}
	module.RelativeDir = relativePath(root, module.Dir)
	file, err := openRegularFileWithinRoot(root, path)
	if err != nil {
		return module, []Diagnostic{{Code: "go_mod_read", Severity: "error", Message: err.Error(), Path: relativePath(root, path), Recoverable: true}}
	}
	defer file.Close()

	var diagnostics []Diagnostic
	scanner := bufio.NewScanner(file)
	section := ""
	sectionStartLine := 0
	sectionEntries := 0
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "//") {
			continue
		}
		syntax := stripLineComment(raw)
		if syntax == "" {
			continue
		}
		if syntax == ")" {
			if section == "" {
				module.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_mod_section", "unmatched closing parenthesis"))
			} else if sectionEntries == 0 && !isSupportedGoModBlock(section) {
				module.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, sectionStartLine, "go_mod_unsupported_directive", fmt.Sprintf("unsupported empty go.mod %q section", section)))
			}
			section = ""
			sectionStartLine = 0
			sectionEntries = 0
			continue
		}
		if strings.HasSuffix(syntax, "(") {
			if section != "" {
				module.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_mod_section", fmt.Sprintf("section %q was not closed before a new section", section)))
			}
			section = strings.TrimSpace(strings.TrimSuffix(syntax, "("))
			sectionStartLine = lineNo
			sectionEntries = 0
			continue
		}
		keyword := section
		value := raw
		inSection := keyword != ""
		if inSection {
			sectionEntries++
		}
		if keyword == "" {
			parts := strings.Fields(raw)
			if len(parts) == 0 {
				continue
			}
			keyword = parts[0]
			value = strings.TrimSpace(strings.TrimPrefix(raw, keyword))
		}
		if inSection && keyword != "require" && keyword != "replace" {
			module.ParseIssues++
			diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_mod_unsupported_directive", fmt.Sprintf("unsupported go.mod %q section entry", keyword)))
			continue
		}

		switch keyword {
		case "module":
			parsed, ok := parseSingleToken(value)
			module.Path = parsed
			if parsed != "" && !ok {
				module.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_mod_module", "could not parse module directive"))
			}
		case "go":
			var ok bool
			module.GoVersion, ok = parseSingleToken(value)
			if !ok {
				module.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_mod_go", "could not parse go directive"))
			}
		case "toolchain":
			var ok bool
			module.Toolchain, ok = parseSingleToken(value)
			if !ok {
				module.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_mod_toolchain", "could not parse toolchain directive"))
			}
		case "require":
			req, ok := parseRequirement(value, lineNo)
			if !ok {
				module.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_mod_require", "could not parse require directive"))
				continue
			}
			module.Requirements = append(module.Requirements, req)
		case "replace":
			repl, ok := parseReplacement(value, lineNo)
			if !ok {
				module.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_mod_replace", "could not parse replace directive"))
				continue
			}
			module.Replacements = append(module.Replacements, repl)
		default:
			module.ParseIssues++
			diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_mod_unsupported_directive", fmt.Sprintf("unsupported go.mod directive %q", keyword)))
		}
	}
	if err := scanner.Err(); err != nil {
		diagnostics = append(diagnostics, Diagnostic{Code: "go_mod_read", Severity: "error", Message: err.Error(), Path: relativePath(root, path), Recoverable: true})
	}
	if section != "" {
		module.ParseIssues++
		diagnostics = append(diagnostics, manifestDiagnostic(root, path, sectionStartLine, "go_mod_section", fmt.Sprintf("unterminated go.mod %q section", section)))
	}
	if module.Path == "" {
		module.ParseIssues++
		module.Path = "local.invalid/" + strings.Trim(strings.ReplaceAll(module.RelativeDir, "/", "-"), ".-")
		if strings.HasSuffix(module.Path, "/") {
			module.Path += "root"
		}
		diagnostics = append(diagnostics, Diagnostic{Code: "go_mod_module_missing", Severity: "warning", Message: "go.mod has no module directive; using a synthetic module path", Path: relativePath(root, path), Recoverable: true})
	}
	sort.Slice(module.Requirements, func(i, j int) bool {
		return module.Requirements[i].Path+"@"+module.Requirements[i].Version < module.Requirements[j].Path+"@"+module.Requirements[j].Version
	})
	sort.Slice(module.Replacements, func(i, j int) bool {
		return replacementKey(module.Replacements[i]) < replacementKey(module.Replacements[j])
	})
	return module, diagnostics
}

func parseGoWork(path, root string) (WorkFile, []Diagnostic) {
	work := WorkFile{Path: path}
	file, err := openRegularFileWithinRoot(root, path)
	if err != nil {
		return work, []Diagnostic{{Code: "go_work_read", Severity: "error", Message: err.Error(), Path: relativePath(root, path), Recoverable: true}}
	}
	defer file.Close()
	var diagnostics []Diagnostic
	section := ""
	sectionStartLine := 0
	sectionEntries := 0
	lineNo := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "//") {
			continue
		}
		syntax := stripLineComment(raw)
		if syntax == "" {
			continue
		}
		if syntax == ")" {
			if section == "" {
				work.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_work_section", "unmatched closing parenthesis"))
			} else if sectionEntries == 0 && !isSupportedGoWorkBlock(section) {
				work.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, sectionStartLine, "go_work_unsupported_directive", fmt.Sprintf("unsupported empty go.work %q section", section)))
			}
			section = ""
			sectionStartLine = 0
			sectionEntries = 0
			continue
		}
		if strings.HasSuffix(syntax, "(") {
			if section != "" {
				work.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_work_section", fmt.Sprintf("section %q was not closed before a new section", section)))
			}
			section = strings.TrimSpace(strings.TrimSuffix(syntax, "("))
			sectionStartLine = lineNo
			sectionEntries = 0
			continue
		}
		keyword := section
		value := raw
		inSection := keyword != ""
		if inSection {
			sectionEntries++
		}
		if keyword == "" {
			parts := strings.Fields(raw)
			if len(parts) == 0 {
				continue
			}
			keyword = parts[0]
			value = strings.TrimSpace(strings.TrimPrefix(raw, keyword))
		}
		if inSection && keyword != "use" && keyword != "replace" {
			work.ParseIssues++
			diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_work_unsupported_directive", fmt.Sprintf("unsupported go.work %q section entry", keyword)))
			continue
		}
		switch keyword {
		case "go":
			var ok bool
			work.GoVersion, ok = parseSingleToken(value)
			if !ok {
				work.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_work_go", "could not parse go directive"))
			}
		case "toolchain":
			var ok bool
			work.Toolchain, ok = parseSingleToken(value)
			if !ok {
				work.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_work_toolchain", "could not parse toolchain directive"))
			}
		case "use":
			use, ok := parseSingleToken(value)
			if !ok {
				work.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_work_use", "could not parse use directive"))
				continue
			}
			work.Uses = append(work.Uses, use)
		case "replace":
			repl, ok := parseReplacement(value, lineNo)
			if !ok {
				work.ParseIssues++
				diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_work_replace", "could not parse replace directive"))
				continue
			}
			work.Replacements = append(work.Replacements, repl)
		default:
			work.ParseIssues++
			diagnostics = append(diagnostics, manifestDiagnostic(root, path, lineNo, "go_work_unsupported_directive", fmt.Sprintf("unsupported go.work directive %q", keyword)))
		}
	}
	if err := scanner.Err(); err != nil {
		diagnostics = append(diagnostics, Diagnostic{Code: "go_work_read", Severity: "error", Message: err.Error(), Path: relativePath(root, path), Recoverable: true})
	}
	if section != "" {
		work.ParseIssues++
		diagnostics = append(diagnostics, manifestDiagnostic(root, path, sectionStartLine, "go_work_section", fmt.Sprintf("unterminated go.work %q section", section)))
	}
	sort.Strings(work.Uses)
	sort.Slice(work.Replacements, func(i, j int) bool {
		return replacementKey(work.Replacements[i]) < replacementKey(work.Replacements[j])
	})
	return work, diagnostics
}

func parseRequirement(line string, lineNo int) (Requirement, bool) {
	indirect := strings.Contains(line, "// indirect")
	fields := strings.Fields(stripLineComment(line))
	if len(fields) != 2 {
		return Requirement{}, false
	}
	path := unquote(fields[0])
	version := unquote(fields[1])
	if path == "" || version == "" {
		return Requirement{}, false
	}
	return Requirement{Path: path, Version: version, Indirect: indirect, Line: lineNo}, true
}

func isSupportedGoModBlock(section string) bool {
	return section == "require" || section == "replace"
}

func isSupportedGoWorkBlock(section string) bool {
	return section == "use" || section == "replace"
}

func parseReplacement(line string, lineNo int) (Replacement, bool) {
	line = stripLineComment(line)
	parts := strings.Split(line, "=>")
	if len(parts) != 2 {
		return Replacement{}, false
	}
	left := strings.Fields(strings.TrimSpace(parts[0]))
	right := strings.Fields(strings.TrimSpace(parts[1]))
	if len(left) < 1 || len(left) > 2 || len(right) < 1 || len(right) > 2 {
		return Replacement{}, false
	}
	repl := Replacement{OldPath: unquote(left[0]), NewPath: unquote(right[0]), Line: lineNo}
	if len(left) == 2 {
		repl.OldVersion = unquote(left[1])
	}
	if len(right) == 2 {
		repl.NewVersion = unquote(right[1])
	}
	return repl, true
}

func stripLineComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return strings.TrimSpace(line[:i])
	}
	return strings.TrimSpace(line)
}

func firstToken(value string) string {
	fields := strings.Fields(stripLineComment(value))
	if len(fields) == 0 {
		return ""
	}
	return unquote(fields[0])
}

func parseSingleToken(value string) (string, bool) {
	fields := strings.Fields(stripLineComment(value))
	if len(fields) != 1 {
		return firstToken(value), false
	}
	parsed := unquote(fields[0])
	return parsed, parsed != ""
}

func unquote(value string) string {
	if len(value) >= 2 && (value[0] == '`' || value[0] == '"') {
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted
		}
	}
	return value
}

func replacementKey(repl Replacement) string {
	return strings.Join([]string{repl.OldPath, repl.OldVersion, repl.NewPath, repl.NewVersion}, "\x00")
}

func manifestDiagnostic(root, path string, line int, code, message string) Diagnostic {
	rel := relativePath(root, path)
	return Diagnostic{
		Code: code, Severity: "warning", Message: message, Path: rel, Recoverable: true,
		Evidence: sourceEvidence(rel, line, 1, line, 1, ""),
	}
}

func skippedMetadataPath(relative string) string {
	return cleanSlash(filepath.Join("__depgraph_skipped__", filepath.FromSlash(relative)))
}

func findManifests(root string, inventory *repositoryInventory) ([]string, []FileCompletion, []Diagnostic, error) {
	var manifests []string
	var skipped []FileCompletion
	var diagnostics []Diagnostic
	entries, err := repositoryFileEntries(root, inventory)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, candidate := range entries {
		path := candidate.path
		entry := candidate.entry
		if entry.Name() == "go.mod" {
			if _, resolveErr := resolveRegularFileWithinRoot(root, path); resolveErr != nil {
				originalPath := relativePath(root, path)
				code := "go_mod_read"
				ledgerPath := originalPath
				if errors.Is(resolveErr, errPathConfinement) {
					code = "path_confinement"
					// Protocol paths are confinement-checked through symlinks. Keep
					// the lexical name in the message, and use a non-existent in-root
					// ledger path so the rejected metadata remains reportable.
					ledgerPath = skippedMetadataPath(originalPath)
				}
				reason := fmt.Sprintf("go.mod %s could not be inventoried: %v", originalPath, resolveErr)
				skipped = append(skipped, FileCompletion{
					Path: ledgerPath, DiscoveredSites: 1, SkippedSites: 1, Skipped: true, Reason: reason,
				})
				diagnostics = append(diagnostics, Diagnostic{
					Code: code, Severity: "warning", Recoverable: true, Path: ledgerPath,
					Message: reason,
				})
				continue
			}
			manifests = append(manifests, path)
		}
	}
	sort.Strings(manifests)
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Path < skipped[j].Path })
	return manifests, skipped, diagnostics, err
}

func isWithinRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func relativePath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return cleanSlash(path)
	}
	return cleanSlash(rel)
}

func shouldSkipDirectory(name string) bool {
	if name == ".git" || name == ".hg" || name == ".svn" || name == "testdata" {
		return true
	}
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

func resolveLocalReplacement(root string, module Module, replacement Replacement) (string, bool, string) {
	if replacement.NewVersion != "" || (!strings.HasPrefix(replacement.NewPath, ".") && !filepath.IsAbs(replacement.NewPath)) {
		return "", false, ""
	}
	path := replacement.NewPath
	if !filepath.IsAbs(path) {
		path = filepath.Join(module.Dir, filepath.FromSlash(path))
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", false, err.Error()
	}
	path = filepath.Clean(path)
	if !isWithinRoot(root, path) {
		return "", false, fmt.Sprintf("local replacement %q is outside the scan root", replacement.NewPath)
	}
	if _, statErr := os.Lstat(path); statErr == nil {
		resolved, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr != nil {
			return "", false, resolveErr.Error()
		}
		resolved = filepath.Clean(resolved)
		if !isWithinRoot(root, resolved) {
			return "", false, fmt.Sprintf("local replacement %q resolves outside the scan root", replacement.NewPath)
		}
		path = resolved
	} else if !os.IsNotExist(statErr) {
		return "", false, statErr.Error()
	}
	return path, true, ""
}
