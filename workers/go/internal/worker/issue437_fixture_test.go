package worker

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var issue437HealthSemanticResolvers = map[string]string{
	"example.com/issue437/cmd.main":         "symbol",
	"example.com/issue437/pkg.Caller":       "symbol",
	"example.com/issue437/pkg.UsedExport":   "symbol",
	"example.com/issue437/pkg.UnusedExport": "symbol",
	"example.com/issue437/pkg.UsedType":     "type",
	"example.com/issue437/pkg.UnusedType":   "type",
}

func TestIssue437HealthFixtureMatchesEmittedGoSemanticNodes(t *testing.T) {
	root := filepath.Join("testdata", "health")
	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Coverage.ProjectCodeExecuted {
		t.Fatal("health fixture scan reported project code execution")
	}
	if !containsString(result.Coverage.Completeness, "semantic-complete") {
		t.Fatalf("health fixture scan is not semantic-complete: %+v", result.Coverage)
	}
	if result.Coverage.FilesDiscovered != 5 || result.Coverage.FilesAnalyzed != 5 || result.Coverage.DependencySites != 4 {
		t.Fatalf("health fixture coverage = %+v, want 5 files and 4 sites", result.Coverage)
	}

	var emitted bytes.Buffer
	if err := Emit(&emitted, "issue437-health-e2e", result); err != nil {
		t.Fatalf("Emit() error = %v", err)
	}
	produced := issue437SemanticNodesFromNDJSON(t, emitted.Bytes())

	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the worker package")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", "..", "..", ".."))
	fixturePath := filepath.Join(repoRoot, "crates", "depgraph-core", "tests", "fixtures", "health", "issue437-go.ndjson")
	fixtureBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read Go health fixture %s: %v", fixturePath, err)
	}
	// Profile/toolchain IDs and environment fields are deliberately excluded
	// from this comparison. Semantic identities, node properties, and relation
	// endpoints are the stable producer/consumer contract.
	fixture := issue437SemanticNodesFromNDJSON(t, fixtureBytes)
	producedRelations := issue437SemanticRelationsFromNDJSON(t, emitted.Bytes())
	fixtureRelations := issue437SemanticRelationsFromNDJSON(t, fixtureBytes)
	if !reflect.DeepEqual(producedRelations, fixtureRelations) {
		t.Fatalf("fixture dependency relations differ from emitted worker relations:\nproducer: %+v\nfixture:  %+v", producedRelations, fixtureRelations)
	}

	if len(produced) != len(issue437HealthSemanticResolvers) {
		t.Fatalf("emitted semantic nodes = %d, want %d: %+v", len(produced), len(issue437HealthSemanticResolvers), produced)
	}
	if len(fixture) != len(issue437HealthSemanticResolvers) {
		t.Fatalf("fixture semantic nodes = %d, want %d: %+v", len(fixture), len(issue437HealthSemanticResolvers), fixture)
	}
	for resolver, kind := range issue437HealthSemanticResolvers {
		producerNode, ok := produced[resolver]
		if !ok {
			t.Fatalf("worker did not emit %s node %q", kind, resolver)
		}
		fixtureNode, ok := fixture[resolver]
		if !ok {
			t.Fatalf("fixture did not contain %s node %q", kind, resolver)
		}
		if !reflect.DeepEqual(producerNode, fixtureNode) {
			t.Fatalf("fixture node %q differs from emitted worker node:\nproducer: %+v\nfixture:  %+v", resolver, producerNode, fixtureNode)
		}
		if producerNode.Kind != kind {
			t.Fatalf("worker node %q kind = %q, want %q", resolver, producerNode.Kind, kind)
		}
		if producerNode.Properties["language"] != "go" {
			t.Fatalf("worker node %q language = %#v, want go", resolver, producerNode.Properties["language"])
		}
		allowed := map[string]bool{
			"canonical_identity": true,
			"language":           true,
			"package_locator":    true,
			"symbol_kind":        kind == "symbol",
			"type_kind":          kind == "type",
		}
		for property := range producerNode.Properties {
			if !allowed[property] {
				t.Fatalf("worker node %q emitted non-worker fixture property %q: %+v", resolver, property, producerNode.Properties)
			}
		}
	}
}

func issue437SemanticNodesFromNDJSON(t *testing.T, data []byte) map[string]Node {
	t.Helper()
	nodes := map[string]Node{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var event struct {
			Event string `json:"event"`
			Node  *Node  `json:"node"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode worker event: %v", err)
		}
		if event.Event != "node_upsert" || event.Node == nil || (event.Node.Kind != "symbol" && event.Node.Kind != "type") {
			continue
		}
		identity, ok := event.Node.Properties["canonical_identity"].(map[string]any)
		if !ok {
			t.Fatalf("semantic node %s has no canonical identity: %+v", event.Node.ID, event.Node)
		}
		resolver, ok := identity["resolver_identity"].(string)
		if !ok || resolver == "" {
			t.Fatalf("semantic node %s has no resolver identity: %+v", event.Node.ID, identity)
		}
		if previous, duplicate := nodes[resolver]; duplicate && !reflect.DeepEqual(previous, *event.Node) {
			t.Fatalf("resolver %q maps to multiple semantic nodes: %+v and %+v", resolver, previous, *event.Node)
		}
		nodes[resolver] = *event.Node
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan worker events: %v", err)
	}
	return nodes
}

type issue437RelationProjection struct {
	Sites []string
	Edges []string
}

func issue437SemanticRelationsFromNDJSON(t *testing.T, data []byte) issue437RelationProjection {
	t.Helper()
	nodes := map[string]Node{}
	sites := map[string]Site{}
	var edges []Edge
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var event struct {
			Event string `json:"event"`
			Node  *Node  `json:"node"`
			Site  *Site  `json:"site"`
			Edge  *Edge  `json:"edge"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode worker relation event: %v", err)
		}
		switch event.Event {
		case "node_upsert":
			if event.Node != nil {
				nodes[event.Node.ID] = *event.Node
			}
		case "dependency_site":
			if event.Site != nil && (event.Site.Kind == "call" || event.Site.Kind == "type_use" || event.Site.Kind == "import") {
				sites[event.Site.ID] = *event.Site
			}
		case "edge_upsert":
			if event.Edge != nil && (event.Edge.Kind == "calls" || event.Edge.Kind == "type_uses" || event.Edge.Kind == "imports") {
				edges = append(edges, *event.Edge)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan worker relation events: %v", err)
	}

	projection := issue437RelationProjection{}
	siteKeys := map[string]string{}
	for _, site := range sites {
		targets := make([]string, 0, len(site.TargetIDs))
		for _, targetID := range site.TargetIDs {
			targets = append(targets, issue437NodeLabel(t, nodes, targetID))
		}
		sort.Strings(targets)
		key := fmt.Sprintf("%s|%s|%s|%s|%s|%s", site.Kind, issue437NodeLabel(t, nodes, site.Source), site.Specifier, strings.Join(targets, ","), site.ResolutionStatus, site.Precision)
		projection.Sites = append(projection.Sites, key)
		siteKeys[site.ID] = key
	}
	for _, edge := range edges {
		siteKey := siteKeys[edge.SiteID]
		if edge.SiteID != "" && siteKey == "" {
			t.Fatalf("relation edge %s references unprojected site %s", edge.ID, edge.SiteID)
		}
		projection.Edges = append(projection.Edges, fmt.Sprintf("%s|%s|%s|%s|%s|%s", edge.Kind, issue437NodeLabel(t, nodes, edge.Source), issue437NodeLabel(t, nodes, edge.Target), edge.Phase, edge.ResolutionStatus, siteKey))
	}
	sort.Strings(projection.Sites)
	sort.Strings(projection.Edges)
	return projection
}

func issue437NodeLabel(t *testing.T, nodes map[string]Node, id string) string {
	t.Helper()
	node, ok := nodes[id]
	if !ok {
		t.Fatalf("relation references missing node %s", id)
	}
	if identity, ok := node.Properties["canonical_identity"].(map[string]any); ok {
		if resolver, ok := identity["resolver_identity"].(string); ok && resolver != "" {
			return node.Kind + ":" + resolver
		}
	}
	return node.Kind + ":" + node.Locator
}
