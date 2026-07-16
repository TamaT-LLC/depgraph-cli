package lib

import "testing"

func TestMessage(t *testing.T) {
	if Message == "" {
		t.Fatal("empty")
	}
}
