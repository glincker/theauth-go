package sqlite

import (
	"encoding/json"
	"fmt"
)

// encodeAttestationClaims stores the verified attestation claims of a device as one JSON
// document. No claims is the empty string, so devices enrolled without hardware evidence
// keep a plain empty column.
func encodeAttestationClaims(m map[string]any) (string, error) {
	if len(m) == 0 {
		return "", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("encode attestation claims: %w", err)
	}
	return string(b), nil
}

func decodeAttestationClaims(s string) (map[string]any, error) {
	if s == "" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, fmt.Errorf("decode attestation claims: %w", err)
	}
	return m, nil
}
