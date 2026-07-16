package model

import "testing"

type internalWorker interface {
	Work(Input) Output
}

var _ internalWorker = Service{}

type internalOnly struct{}

func (internalOnly) Clash() {}

func TestInternal(t *testing.T) {
	pair := Build(Input{Value: "internal"})
	if pair.First.Value == "" {
		t.Fatal("empty")
	}
}
