package lib_test

import (
	"testing"

	"example.com/app/lib"
)

func TestExternal(t *testing.T) {
	if lib.Message == "" {
		t.Fatal("empty")
	}
}
