package worker

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
)

func TestEmitProtocolEnvelopeAndSequence(t *testing.T) {
	result, err := Scan(fixtureRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Emit(&output, "scan-fixture", result); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	line := 0
	scanner := bufio.NewScanner(&output)
	for scanner.Scan() {
		line++
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("line %d is not JSON: %v", line, err)
		}
		if event["protocol_version"] != ProtocolVersion || event["scan_id"] != "scan-fixture" || event["adapter"] != AdapterName || event["adapter_version"] != AdapterVersion {
			t.Fatalf("line %d has invalid common fields: %+v", line, event)
		}
		if got := int(event["seq"].(float64)); got != line {
			t.Fatalf("line %d has seq %d", line, got)
		}
		eventName := event["event"].(string)
		seen[eventName] = true
		switch eventName {
		case "scan_started":
			if executed, ok := event["project_code_executed"].(bool); !ok || executed {
				t.Fatalf("scan_started has invalid project_code_executed: %+v", event)
			}
		case "profile_declared":
			if event["profile"] == nil {
				t.Fatal("profile_declared lacks profile")
			}
		case "node_upsert":
			if event["node"] == nil {
				t.Fatal("node_upsert lacks node")
			}
		case "dependency_site":
			if event["site"] == nil {
				t.Fatal("dependency_site lacks site")
			}
		case "edge_upsert":
			if event["edge"] == nil {
				t.Fatal("edge_upsert lacks edge")
			}
		case "diagnostic":
			if event["diagnostic"] == nil {
				t.Fatal("diagnostic lacks diagnostic")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{
		"scan_started", "profile_declared", "node_upsert", "dependency_site", "edge_upsert",
		"diagnostic", "file_completed", "profile_completed", "scan_completed",
	} {
		if !seen[event] {
			t.Fatalf("missing event type %q", event)
		}
	}
}

func TestEmitIsByteDeterministic(t *testing.T) {
	result, err := Scan(fixtureRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	var first, second bytes.Buffer
	if err := Emit(&first, "same-scan", result); err != nil {
		t.Fatal(err)
	}
	if err := Emit(&second, "same-scan", result); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("NDJSON output is not byte deterministic")
	}
}
