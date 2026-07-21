//go:build cgo

package model

/*
#cgo LDFLAGS: -lm
#include <stdlib.h>
*/
import "C"

//export NativeBoundaryCallback
func NativeBoundaryCallback() {}
