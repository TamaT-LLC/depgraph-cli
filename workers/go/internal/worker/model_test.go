package worker

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAlwaysConditionUsesCanonicalBooleanAST(t *testing.T) {
	encoded, err := json.Marshal(AlwaysCondition())
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"op":"all","conditions":[]}` {
		t.Fatalf("unexpected always condition: %s", encoded)
	}

	condition := canonicalCondition(Condition{
		Op: "any",
		Conditions: []Condition{
			{Op: "defined", Key: "go.build_tag:linux"},
			AlwaysCondition(),
		},
	})
	encoded, err = json.Marshal(condition)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"op":"all","conditions":[]}` {
		t.Fatalf("true must absorb any(): %s", encoded)
	}
	if strings.Contains(string(encoded), `"op":"true"`) {
		t.Fatalf("unsupported true operator leaked: %s", encoded)
	}
}

func TestContentHashUsesRawBytesAndExplicitAlgorithmPrefix(t *testing.T) {
	const want = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := contentHash([]byte("abc")); got != want {
		t.Fatalf("contentHash(abc) = %q, want %q", got, want)
	}
}
