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
