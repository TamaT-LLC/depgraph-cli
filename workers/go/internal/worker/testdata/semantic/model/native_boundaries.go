//go:build !windows

package model

import (
	_ "plugin"
	_ "unsafe"
)

//go:linkname runtimeBoundary runtime.nanotime
func runtimeBoundary() int64

func AssemblyBoundary()
