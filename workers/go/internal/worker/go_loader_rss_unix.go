//go:build unix

package worker

import (
	"runtime"
	"syscall"
)

// rusageMaxRSSBytes reads ru_maxrss for the calling process or its reaped
// children. Linux and the BSDs report kilobytes; Darwin reports bytes.
func rusageMaxRSSBytes(children bool) int64 {
	who := syscall.RUSAGE_SELF
	if children {
		who = syscall.RUSAGE_CHILDREN
	}
	var usage syscall.Rusage
	if err := syscall.Getrusage(who, &usage); err != nil {
		return 0
	}
	value := int64(usage.Maxrss)
	if value <= 0 {
		return 0
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		return value
	}
	return value * 1024
}
