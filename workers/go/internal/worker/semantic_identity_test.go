package worker

import (
	"bytes"
	"testing"
)

func TestStableIDFromValueMatchesProtocolKnownHash(t *testing.T) {
	got := stableIDFromValue("file", map[string]any{"path": "src/lib.rs"})
	const want = "file:sha256:54047b442992a19c4f9c11c7c70f2fe9a8344276b07cdbe6b65c218cffa37ecd"
	if got != want {
		t.Fatalf("stable ID = %q, want %q", got, want)
	}
}

func TestCanonicalJSONSortsNestedKeysWithoutEscapingHTML(t *testing.T) {
	value := map[string]any{
		"z": []any{map[string]any{"b": 2, "a": "<&>"}, 3},
		"a": true,
	}
	got, err := canonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"a":true,"z":[{"a":"<&>","b":2},3]}`
	if string(got) != want {
		t.Fatalf("canonical JSON = %s, want %s", got, want)
	}
	if bytes.HasSuffix(got, []byte{'\n'}) {
		t.Fatalf("canonical JSON retains encoder newline: %q", got)
	}
}

func TestStableIDFromValuePreservesArrayOrder(t *testing.T) {
	forward := stableIDFromValue("instance", map[string]any{
		"type_arguments": []any{"example.com/p.A", "example.com/p.B"},
	})
	reversed := stableIDFromValue("instance", map[string]any{
		"type_arguments": []any{"example.com/p.B", "example.com/p.A"},
	})
	if forward == reversed {
		t.Fatalf("array order was erased: both IDs are %q", forward)
	}
}

func TestCanonicalJSONResortsCustomMarshalJSONObjects(t *testing.T) {
	got, err := canonicalJSON(map[string]any{"condition": AlwaysCondition()})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"condition":{"conditions":[],"op":"all"}}`
	if string(got) != want {
		t.Fatalf("canonical JSON = %s, want %s", got, want)
	}
}
