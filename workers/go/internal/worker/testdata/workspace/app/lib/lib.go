//go:build linux && amd64

package lib

/*
#cgo LDFLAGS: -lm
#include <stdlib.h>
*/
import "C"

import _ "embed"

//go:embed assets/*.txt
var content string

//go:generate sh -c "touch generator-was-run"

const Message = "hello"
