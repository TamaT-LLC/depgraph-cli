package main

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/TamaT-LLC/depgraph-cli/workers/go/internal/issue437golden"
)

// issue437AssertRunGolden compares the stream emitted through run(), rather
// than calling worker.Scan directly. The shared projection retains event
// order, sequence numbers, file nodes, all sites and edges (including
// contains and declares), file completions, and both completion envelopes.
func issue437AssertRunGolden(t *testing.T, produced, fixture []byte) {
	t.Helper()
	got, err := issue437golden.NormalizeNDJSON(produced)
	if err != nil {
		t.Fatalf("normalize run() Go stream: %v", err)
	}
	want, err := issue437golden.NormalizeNDJSON(fixture)
	if err != nil {
		t.Fatalf("normalize Go fixture golden: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		wantJSON, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("run() Go golden stream differs:\nproducer:\n%s\nfixture:\n%s", gotJSON, wantJSON)
	}
}
