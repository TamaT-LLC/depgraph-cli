package issue437golden

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestNormalizeNDJSONCanonicalizesHostEventOrderAndSequence(t *testing.T) {
	darwin, err := NormalizeNDJSON(testGoldenStream("darwin", false))
	if err != nil {
		t.Fatalf("normalize Darwin stream: %v", err)
	}
	linux, err := NormalizeNDJSON(testGoldenStream("linux", true))
	if err != nil {
		t.Fatalf("normalize Linux stream: %v", err)
	}
	if !reflect.DeepEqual(darwin, linux) {
		darwinJSON, _ := json.MarshalIndent(darwin, "", "  ")
		linuxJSON, _ := json.MarshalIndent(linux, "", "  ")
		t.Fatalf("host streams differ after logical ordering:\nDarwin:\n%s\nLinux:\n%s", darwinJSON, linuxJSON)
	}
	for index, event := range linux {
		if got, want := event["seq"], float64(index+1); got != want {
			t.Fatalf("normalized event %d seq = %#v, want %v", index, got, want)
		}
	}
}

func TestNormalizeNDJSONSortsTargetIDsAfterLogicalSubstitution(t *testing.T) {
	darwin, err := NormalizeNDJSON(testGoldenStreamWithTwoTargets("darwin", false))
	if err != nil {
		t.Fatalf("normalize Darwin stream: %v", err)
	}
	linux, err := NormalizeNDJSON(testGoldenStreamWithTwoTargets("linux", true))
	if err != nil {
		t.Fatalf("normalize Linux stream: %v", err)
	}
	if !reflect.DeepEqual(darwin, linux) {
		darwinJSON, _ := json.MarshalIndent(darwin, "", "  ")
		linuxJSON, _ := json.MarshalIndent(linux, "", "  ")
		t.Fatalf("host streams differ after logical target ordering:\nDarwin:\n%s\nLinux:\n%s", darwinJSON, linuxJSON)
	}

	for _, event := range darwin {
		if event["event"] != "dependency_site" {
			continue
		}
		site, ok := event["site"].(map[string]any)
		if !ok {
			t.Fatalf("dependency site is not an object: %#v", event["site"])
		}
		got, ok := site["target_ids"].([]any)
		if !ok {
			t.Fatalf("dependency site target_ids is not an array: %#v", site["target_ids"])
		}
		want := []any{
			"profile-node:symbol:example.com/p.Entry",
			"profile-node:symbol:example.com/p.Other",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("normalized target_ids = %#v, want %#v", got, want)
		}
		return
	}
	t.Fatal("normalized stream has no dependency_site event")
}

func TestNormalizeNDJSONCanonicalizesCallgraphAndSSADiagnostics(t *testing.T) {
	darwin, err := NormalizeNDJSON(testGoldenStreamWithDiagnostics("darwin", false))
	if err != nil {
		t.Fatalf("normalize Darwin stream: %v", err)
	}
	linux, err := NormalizeNDJSON(testGoldenStreamWithDiagnostics("linux", true))
	if err != nil {
		t.Fatalf("normalize Linux stream: %v", err)
	}
	if !reflect.DeepEqual(darwin, linux) {
		darwinJSON, _ := json.MarshalIndent(darwin, "", "  ")
		linuxJSON, _ := json.MarshalIndent(linux, "", "  ")
		t.Fatalf("host streams differ after diagnostic normalization:\nDarwin:\n%s\nLinux:\n%s", darwinJSON, linuxJSON)
	}
}

func TestNormalizeNDJSONRejectsUnknownDiagnosticReferences(t *testing.T) {
	events := decodeGoldenStream(t, testGoldenStreamWithDiagnostics("darwin", false))
	for _, event := range events {
		if event["event"] != "diagnostic" {
			continue
		}
		diagnostic, ok := event["diagnostic"].(map[string]any)
		if !ok {
			t.Fatalf("diagnostic is not an object: %#v", event["diagnostic"])
		}
		properties, ok := diagnostic["properties"].(map[string]any)
		if !ok {
			t.Fatalf("diagnostic properties are not an object: %#v", diagnostic["properties"])
		}
		if diagnostic["code"] == "go_callgraph_limit" {
			properties["site_id"] = "site:unknown"
			if _, err := NormalizeNDJSON(encodeGoldenEvents(t, events)); err == nil {
				t.Fatal("NormalizeNDJSON accepted an unknown diagnostic site reference")
			}
			return
		}
	}
	t.Fatal("diagnostic test stream has no callgraph diagnostic")
}

func TestNormalizeNDJSONRejectsUnknownAndMismatchedProfileReferences(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]map[string]any)
	}{
		{
			name: "scan id mismatch",
			mutate: func(events []map[string]any) {
				events[2]["scan_id"] = "scan:other"
			},
		},
		{
			name: "profile id unknown",
			mutate: func(events []map[string]any) {
				events[len(events)-2]["profile_id"] = "profile:unknown"
			},
		},
		{
			name: "profile ids unknown",
			mutate: func(events []map[string]any) {
				events[0]["profile_ids"] = []any{"profile:unknown"}
			},
		},
		{
			name: "profile declaration not started",
			mutate: func(events []map[string]any) {
				events[1]["profile"].(map[string]any)["id"] = "profile:other"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			events := decodeGoldenStream(t, testGoldenStream("darwin", false))
			test.mutate(events)
			if _, err := NormalizeNDJSON(encodeGoldenEvents(t, events)); err == nil {
				t.Fatalf("NormalizeNDJSON accepted malformed %s stream", test.name)
			}
		})
	}
}

func testGoldenStream(host string, reverseSemanticEvents bool) []byte {
	profileID := "profile:" + host
	scanID := "scan:" + host
	profile := map[string]any{
		"id": profileID, "language": "go", "toolchain": "go1.26.1", "command": "scan",
		"target": host + "-amd64", "features": []any{},
		"environment": map[string]any{"CGO_ENABLED": "0", "GOARCH": "amd64", "GOOS": host, "GO_TAGS": ""},
		"properties":  map[string]any{"safe_scan": "true"},
	}
	fileID := "file:" + host
	symbolID := "symbol:" + host
	nodes := []map[string]any{
		{"id": fileID, "kind": "file", "locator": "file.go", "display_name": "file.go", "properties": map[string]any{"language": "go", "package_name": "pkg", "package_path": "example.com/p"}},
		{"id": symbolID, "kind": "symbol", "locator": "go-symbol:example.com/p.Entry", "display_name": "Entry", "properties": map[string]any{
			"canonical_identity": map[string]any{"identity_kind": "named", "language": "go", "package_locator": "go:example.com/p@workspace#example.com/p", "resolver_identity": "example.com/p.Entry", "symbol_kind": "function"},
			"language":           "go", "package_locator": "go:example.com/p@workspace#example.com/p", "symbol_kind": "function",
		}},
	}
	if reverseSemanticEvents {
		nodes[0], nodes[1] = nodes[1], nodes[0]
	}
	base := func(event string, seq int, fields map[string]any) map[string]any {
		record := map[string]any{
			"adapter": "go", "adapter_version": "0.5.4", "event": event,
			"protocol_version": "1.0", "scan_id": scanID, "seq": float64(seq),
		}
		for key, value := range fields {
			record[key] = value
		}
		return record
	}
	events := []map[string]any{
		base("scan_started", 101, map[string]any{"root": ".", "profile_ids": []any{profileID}, "project_code_executed": false, "safe_mode": true}),
		base("profile_declared", 102, map[string]any{"profile": profile}),
		base("node_upsert", 103, map[string]any{"node": nodes[0]}),
		base("node_upsert", 104, map[string]any{"node": nodes[1]}),
		base("dependency_site", 105, map[string]any{"site": map[string]any{
			"id": "site:" + host, "source": fileID, "kind": "call", "specifier": "example.com/p.Entry", "resolution_status": "resolved",
			"target_ids": []any{symbolID}, "profile_id": profileID, "condition": map[string]any{"op": "all", "conditions": []any{}}, "precision": "exact", "evidence": []any{},
		}}),
		base("edge_upsert", 106, map[string]any{"edge": map[string]any{
			"id": "edge:" + host, "source": fileID, "target": symbolID, "kind": "calls", "site_id": "site:" + host,
			"phase": "semantic", "environment": "any", "resolution_status": "resolved", "profile_id": profileID,
			"condition": map[string]any{"op": "all", "conditions": []any{}}, "precision": "exact", "generated": false, "evidence": []any{},
		}}),
		base("file_completed", 107, map[string]any{"path": "file.go", "discovered_sites": 1, "emitted_sites": 1, "skipped_sites": 0, "skipped": false}),
		base("profile_completed", 108, map[string]any{"profile_id": profileID, "coverage": map[string]any{"profiles": 1, "files_discovered": 1, "files_analyzed": 1, "dependency_sites": 1, "resolved": 1, "completeness": []any{"semantic-complete"}, "project_code_executed": false, "reasons": []any{}}}),
		base("scan_completed", 109, map[string]any{"coverage": map[string]any{"profiles": 1, "files_discovered": 1, "files_analyzed": 1, "dependency_sites": 1, "resolved": 1, "completeness": []any{"semantic-complete"}, "project_code_executed": false, "reasons": []any{}}}),
	}
	if reverseSemanticEvents {
		// Keep lifecycle envelopes intact while simulating a host that emitted
		// graph collections in the opposite order and assigned different seqs.
		events[2], events[3] = events[3], events[2]
		events[4], events[5] = events[5], events[4]
	}
	return encodeGoldenEventsWithoutTesting(events)
}

func testGoldenStreamWithTwoTargets(host string, reverseSemanticEvents bool) []byte {
	events, err := eventsFromNDJSON(testGoldenStream(host, reverseSemanticEvents))
	if err != nil {
		panic(fmt.Sprintf("decode two-target test stream: %v", err))
	}
	secondID := "symbol:zzzz-" + host
	if host == "darwin" {
		// The raw producer order is intentionally reversed between hosts. The
		// logical resolver identity must be sorted after ID substitution.
		secondID = "symbol:aardvark-" + host
	}
	events = append(events, map[string]any{
		"adapter": "go", "adapter_version": "0.5.4", "event": "node_upsert",
		"protocol_version": "1.0", "scan_id": "scan:" + host, "seq": float64(110),
		"node": map[string]any{
			"id": secondID, "kind": "symbol", "locator": "go-symbol:example.com/p.Other",
			"display_name": "Other", "properties": map[string]any{
				"canonical_identity": map[string]any{
					"identity_kind": "named", "language": "go",
					"package_locator":   "go:example.com/p@workspace#example.com/p",
					"resolver_identity": "example.com/p.Other", "symbol_kind": "function",
				},
				"language": "go", "package_locator": "go:example.com/p@workspace#example.com/p",
				"symbol_kind": "function",
			},
		},
	})
	for _, event := range events {
		if event["event"] != "dependency_site" {
			continue
		}
		site := event["site"].(map[string]any)
		if host == "darwin" {
			site["target_ids"] = []any{secondID, "symbol:" + host}
		} else {
			site["target_ids"] = []any{"symbol:" + host, secondID}
		}
		break
	}
	return encodeGoldenEventsWithoutTesting(events)
}

func testGoldenStreamWithDiagnostics(host string, reverseSemanticEvents bool) []byte {
	events, err := eventsFromNDJSON(testGoldenStream(host, reverseSemanticEvents))
	if err != nil {
		panic(fmt.Sprintf("decode diagnostic test stream: %v", err))
	}
	profileID := "profile:" + host
	scanID := "scan:" + host
	siteID := "site:" + host
	fileID := "file:" + host
	base := func(seq float64, id, code, message string, properties map[string]any) map[string]any {
		return map[string]any{
			"adapter": "go", "adapter_version": "0.5.4", "event": "diagnostic",
			"protocol_version": "1.0", "scan_id": scanID, "seq": seq,
			"diagnostic": map[string]any{
				"id": id, "code": code, "severity": "warning", "message": message,
				"profile_id": profileID, "path": "file.go", "start_line": float64(1),
				"start_column": float64(1), "end_line": float64(1), "end_column": float64(5),
				"evidence": []any{}, "properties": properties, "recoverable": true,
			},
		}
	}
	callgraph := base(111, "diagnostic:callgraph:"+host, "go_callgraph_limit", "call graph boundary", map[string]any{
		"boundary": "native", "reason": "outside_ssa", "site_id": siteID,
		"context": map[string]any{"node_id": fileID},
	})
	ssa := base(112, "diagnostic:ssa:"+host, "go_ssa_partial_program", "incomplete SSA", map[string]any{
		"algorithm": "cha", "reason": "incomplete_program", "fallback_reason": "incomplete_program_fallback",
	})
	if reverseSemanticEvents {
		events = append(events, ssa, callgraph)
	} else {
		events = append(events, callgraph, ssa)
	}
	return encodeGoldenEventsWithoutTesting(events)
}

func decodeGoldenStream(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	events, err := eventsFromNDJSON(data)
	if err != nil {
		t.Fatalf("decode test stream: %v", err)
	}
	return events
}

func encodeGoldenEvents(t *testing.T, events []map[string]any) []byte {
	t.Helper()
	return encodeGoldenEventsWithoutTesting(events)
}

func encodeGoldenEventsWithoutTesting(events []map[string]any) []byte {
	var output bytes.Buffer
	for _, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			panic(fmt.Sprintf("encode test stream: %v", err))
		}
		output.Write(encoded)
		output.WriteByte('\n')
	}
	return output.Bytes()
}
