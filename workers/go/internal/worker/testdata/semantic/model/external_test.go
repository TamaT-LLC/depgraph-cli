package model_test

import (
	"testing"

	"example.com/semantic/model"
)

type externalOnly interface{ Clash() }

func TestExternal(t *testing.T) {
	var worker model.Worker = model.Service{}
	result := worker.Work(model.Input{Value: "external"})
	pair := model.Pair[model.Output, model.Input]{First: result}
	if pair.First.Value == "" {
		t.Fatal("empty")
	}
}
