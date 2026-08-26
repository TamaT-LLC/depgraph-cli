package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	ProtocolVersion = "1.0"
	AdapterName     = "go"
	AdapterVersion  = "0.5.4"
)

type Condition struct {
	Op         string      `json:"op"`
	Conditions []Condition `json:"conditions,omitempty"`
	Condition  *Condition  `json:"condition,omitempty"`
	Key        string      `json:"key,omitempty"`
	Value      string      `json:"value,omitempty"`
	Values     []string    `json:"values,omitempty"`
}

func AlwaysCondition() Condition {
	return Condition{Op: "all", Conditions: []Condition{}}
}

func (c Condition) MarshalJSON() ([]byte, error) {
	if c.Op == "all" || c.Op == "any" {
		conditions := c.Conditions
		if conditions == nil {
			conditions = []Condition{}
		}
		return json.Marshal(struct {
			Op         string      `json:"op"`
			Conditions []Condition `json:"conditions"`
		}{Op: c.Op, Conditions: conditions})
	}
	type conditionAlias Condition
	return json.Marshal(conditionAlias(c))
}

func isAlwaysCondition(c Condition) bool {
	return c.Op == "all" && len(c.Conditions) == 0
}

func canonicalCondition(c Condition) Condition {
	for i := range c.Conditions {
		c.Conditions[i] = canonicalCondition(c.Conditions[i])
	}
	if c.Condition != nil {
		v := canonicalCondition(*c.Condition)
		if c.Op == "not" && v.Op == "not" && v.Condition != nil {
			return canonicalCondition(*v.Condition)
		}
		c.Condition = &v
	}
	if c.Op == "all" || c.Op == "any" {
		flattened := make([]Condition, 0, len(c.Conditions))
		for _, child := range c.Conditions {
			if isAlwaysCondition(child) {
				if c.Op == "any" {
					return AlwaysCondition()
				}
				continue
			}
			if child.Op == c.Op && child.Condition == nil && child.Key == "" && child.Value == "" {
				flattened = append(flattened, child.Conditions...)
			} else {
				flattened = append(flattened, child)
			}
		}
		c.Conditions = flattened
		sort.Slice(c.Conditions, func(i, j int) bool {
			left, _ := json.Marshal(c.Conditions[i])
			right, _ := json.Marshal(c.Conditions[j])
			return string(left) < string(right)
		})
		unique := c.Conditions[:0]
		last := ""
		for index, condition := range c.Conditions {
			encoded, _ := json.Marshal(condition)
			if index == 0 || string(encoded) != last {
				unique = append(unique, condition)
				last = string(encoded)
			}
		}
		c.Conditions = unique
		if c.Op == "all" && len(c.Conditions) == 0 {
			return AlwaysCondition()
		}
		if len(c.Conditions) == 1 {
			return c.Conditions[0]
		}
	}
	if c.Op == "in" {
		sort.Strings(c.Values)
		unique := c.Values[:0]
		for _, value := range c.Values {
			if len(unique) == 0 || unique[len(unique)-1] != value {
				unique = append(unique, value)
			}
		}
		c.Values = unique
		if len(c.Values) == 1 {
			return Condition{Op: "eq", Key: c.Key, Value: c.Values[0]}
		}
	}
	return c
}

type Evidence struct {
	Kind             string         `json:"kind"`
	Extractor        string         `json:"extractor"`
	ExtractorVersion string         `json:"extractor_version"`
	Path             string         `json:"path"`
	StartLine        int            `json:"start_line"`
	StartColumn      int            `json:"start_column"`
	EndLine          int            `json:"end_line"`
	EndColumn        int            `json:"end_column"`
	Detail           string         `json:"detail,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type Node struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	Locator     string         `json:"locator"`
	DisplayName string         `json:"display_name"`
	Properties  map[string]any `json:"properties,omitempty"`
}

type Site struct {
	ID               string     `json:"id"`
	Source           string     `json:"source"`
	Kind             string     `json:"kind"`
	Specifier        string     `json:"specifier"`
	ResolutionStatus string     `json:"resolution_status"`
	TargetIDs        []string   `json:"target_ids"`
	ProfileID        string     `json:"profile_id"`
	Condition        Condition  `json:"condition"`
	Precision        string     `json:"precision"`
	Evidence         []Evidence `json:"evidence"`
	Reason           string     `json:"reason,omitempty"`
}

type Edge struct {
	ID               string     `json:"id"`
	Source           string     `json:"source"`
	Target           string     `json:"target"`
	Kind             string     `json:"kind"`
	SiteID           string     `json:"site_id,omitempty"`
	Phase            string     `json:"phase"`
	Environment      string     `json:"environment"`
	ResolutionStatus string     `json:"resolution_status"`
	ProfileID        string     `json:"profile_id"`
	Condition        Condition  `json:"condition"`
	Precision        string     `json:"precision"`
	Generated        bool       `json:"generated"`
	Evidence         []Evidence `json:"evidence"`
}

type Profile struct {
	ID             string            `json:"id"`
	Language       string            `json:"language"`
	Toolchain      string            `json:"toolchain"`
	Command        string            `json:"command"`
	Target         string            `json:"target"`
	Features       []string          `json:"features"`
	Environment    map[string]string `json:"environment"`
	SourceRevision *string           `json:"source_revision,omitempty"`
	Properties     map[string]string `json:"properties"`
}

type Diagnostic struct {
	ID          string         `json:"id"`
	Code        string         `json:"code"`
	Severity    string         `json:"severity"`
	Message     string         `json:"message"`
	ProfileID   string         `json:"profile_id,omitempty"`
	Path        string         `json:"path,omitempty"`
	StartLine   int            `json:"start_line,omitempty"`
	StartColumn int            `json:"start_column,omitempty"`
	EndLine     int            `json:"end_line,omitempty"`
	EndColumn   int            `json:"end_column,omitempty"`
	Evidence    []Evidence     `json:"evidence,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
	Recoverable bool           `json:"recoverable"`
}

type Coverage struct {
	Profiles            int      `json:"profiles"`
	FilesDiscovered     int      `json:"files_discovered"`
	FilesAnalyzed       int      `json:"files_analyzed"`
	FilesSkipped        int      `json:"files_skipped"`
	DependencySites     int      `json:"dependency_sites"`
	Resolved            int      `json:"resolved"`
	Candidates          int      `json:"candidates"`
	External            int      `json:"external"`
	Unresolved          int      `json:"unresolved"`
	UnsupportedSyntax   int      `json:"unsupported_syntax"`
	ProjectCodeExecuted bool     `json:"project_code_executed"`
	Completeness        []string `json:"completeness"`
	Reasons             []string `json:"reasons"`
}

type FileCompletion struct {
	Path            string `json:"path"`
	DiscoveredSites int    `json:"discovered_sites"`
	EmittedSites    int    `json:"emitted_sites"`
	SkippedSites    int    `json:"skipped_sites"`
	Skipped         bool   `json:"skipped"`
	Reason          string `json:"reason,omitempty"`
}

type Result struct {
	Root        string
	Profile     Profile
	Nodes       []Node
	Sites       []Site
	Edges       []Edge
	Diagnostics []Diagnostic
	Files       []FileCompletion
	Coverage    Coverage
}

func stableID(kind, workspace string, parts ...string) string {
	// encoding/json sorts map keys, producing the same compact canonical JSON
	// object order used by the Rust protocol implementation.
	b, err := json.Marshal(map[string]any{"kind": kind, "parts": parts, "workspace": workspace})
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return kind + ":sha256:" + hex.EncodeToString(sum[:])
}

func contentHash(contents []byte) string {
	sum := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func profileScopedID(kind, workspace, profileID string, parts ...string) string {
	canonicalParts := make([]string, 0, len(parts)+2)
	canonicalParts = append(canonicalParts, "profile", profileID)
	canonicalParts = append(canonicalParts, parts...)
	return stableID(kind, workspace, canonicalParts...)
}

func edgeID(workspace string, edge Edge) string {
	return profileScopedID("edge", workspace, edge.ProfileID, edge.Source, edge.Target, edge.Kind, edge.SiteID)
}

func addNode(nodes map[string]Node, node Node) error {
	if old, ok := nodes[node.ID]; ok {
		oldJSON, _ := json.Marshal(old)
		newJSON, _ := json.Marshal(node)
		if string(oldJSON) != string(newJSON) {
			return fmt.Errorf("conflicting node identity %s", node.ID)
		}
		return nil
	}
	nodes[node.ID] = node
	return nil
}

func sortResult(result *Result) {
	sort.Slice(result.Nodes, func(i, j int) bool { return result.Nodes[i].ID < result.Nodes[j].ID })
	sort.Slice(result.Sites, func(i, j int) bool { return result.Sites[i].ID < result.Sites[j].ID })
	sort.Slice(result.Edges, func(i, j int) bool { return result.Edges[i].ID < result.Edges[j].ID })
	sort.Slice(result.Diagnostics, func(i, j int) bool {
		return result.Diagnostics[i].ID < result.Diagnostics[j].ID
	})
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	for i := range result.Sites {
		sort.Strings(result.Sites[i].TargetIDs)
		result.Sites[i].Condition = canonicalCondition(result.Sites[i].Condition)
	}
	for i := range result.Edges {
		result.Edges[i].Condition = canonicalCondition(result.Edges[i].Condition)
	}
}

func cleanSlash(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	path = strings.TrimPrefix(path, "./")
	if path == "" {
		return "."
	}
	return path
}
