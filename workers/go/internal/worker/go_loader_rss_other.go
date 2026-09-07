//go:build !unix

package worker

// rusageMaxRSSBytes is unavailable outside Unix; callers treat zero as
// "not measurable" and omit the corresponding evidence.
func rusageMaxRSSBytes(bool) int64 {
	return 0
}
