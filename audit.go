package theauth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// redactedMarker is the literal string that replaces secret-flavored values
// in audit metadata. Exported via SeededSecretKeys for callers wanting to
// build their own redactor on the same key list.
const redactedMarker = "[REDACTED]"

// seededSecretKeys is the case-insensitive key blocklist applied by the
// default redactor at any nesting depth. The list intentionally errs on the
// side of over-redaction: better to mask a harmless field than to leak a
// real secret.
var seededSecretKeys = map[string]struct{}{
	"password":      {},
	"secret":        {},
	"token":         {},
	"code":          {},
	"refresh_token": {},
	"access_token":  {},
}

// SeededSecretKeys returns a copy of the case-insensitive key blocklist
// applied by the default redactor. Callers extending the redactor should
// merge this slice with their own additions.
func SeededSecretKeys() []string {
	out := make([]string, 0, len(seededSecretKeys))
	for k := range seededSecretKeys {
		out = append(out, k)
	}
	return out
}

// DefaultRedactor masks values for keys named password, secret, token, code,
// refresh_token, access_token (case-insensitive) at any nesting depth.
// Nested maps and []any are descended; primitive values are kept as-is.
// Returns the same map (mutated in place) for chaining.
//
// Applied once at emit time. A custom Config.Audit.Redactor receives the
// raw metadata and may strip/rename additional fields.
//
// Perf re-audit 2026-06-21 (item 4): key matching now uses
// strings.EqualFold instead of strings.ToLower(k) per call, avoiding a
// heap allocation per metadata key on the hot emit path.
func DefaultRedactor(metadata map[string]any) map[string]any {
	if metadata == nil {
		return nil
	}
	for k, v := range metadata {
		if isSecretKey(k) {
			metadata[k] = redactedMarker
			continue
		}
		metadata[k] = redactValue(v)
	}
	return metadata
}

// isSecretKey reports whether k matches any entry in seededSecretKeys
// using a case-insensitive comparison. EqualFold avoids the per-call
// ToLower allocation of the previous implementation.
func isSecretKey(k string) bool {
	for candidate := range seededSecretKeys {
		if strings.EqualFold(k, candidate) {
			return true
		}
	}
	return false
}

// redactValue recurses into nested maps and slices, applying the same key
// blocklist at every depth. Scalars are returned unchanged.
func redactValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return DefaultRedactor(x)
	case []any:
		for i, elem := range x {
			x[i] = redactValue(elem)
		}
		return x
	case []map[string]any:
		for i := range x {
			x[i] = DefaultRedactor(x[i])
		}
		return x
	default:
		return v
	}
}

// HashEmailForAudit returns sha256(lowercase(email)) hex-encoded. Used by
// emit sites that want to correlate audit rows by email without storing the
// raw plaintext.
func HashEmailForAudit(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}
