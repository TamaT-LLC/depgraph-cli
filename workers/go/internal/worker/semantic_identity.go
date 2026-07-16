package worker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// canonicalJSON serializes a value using the canonical JSON rules shared with
// depgraph-protocol: object keys are sorted recursively, array order is
// preserved, insignificant whitespace is omitted, and HTML characters remain
// unescaped. json.Encoder appends one newline, which is not part of the
// canonical representation.
func canonicalJSON(value any) ([]byte, error) {
	// Normalize through JSON first so values with a custom MarshalJSON method
	// (notably Condition) cannot preserve a non-canonical struct field order.
	// The second encoding then sorts every object key recursively.
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}

// stableIDFromValue produces the protocol ID
// <namespace>:sha256:<lowercase hex> from a canonicalizable JSON value.
func stableIDFromValue(namespace string, value any) string {
	canonical, err := canonicalJSON(value)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(canonical)
	return namespace + ":sha256:" + hex.EncodeToString(digest[:])
}
