package worker

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// goSelfPeakRSSBytes reports the worker's own high-water resident set size.
// Linux exposes VmHWM in /proc/self/status; other Unix systems fall back to
// getrusage(RUSAGE_SELF). Zero means the value is not measurable here.
func goSelfPeakRSSBytes() int64 {
	if value := procStatusKilobytes("VmHWM:"); value > 0 {
		return value * 1024
	}
	return rusageMaxRSSBytes(false)
}

// goChildMaxRSSBytes reports the largest resident set size among reaped child
// processes (go list and the compilers it spawns). It is a process-lifetime
// maximum, so it can only grow across successive loads.
func goChildMaxRSSBytes() int64 {
	return rusageMaxRSSBytes(true)
}

func procStatusKilobytes(prefix string) int64 {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, prefix))
		if len(fields) == 0 {
			return 0
		}
		value, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return 0
		}
		return value
	}
	return 0
}
