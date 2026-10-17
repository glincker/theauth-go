package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// redactedMarker replaces secret-flavored values in audit metadata.
const redactedMarker = "[REDACTED]"

// seededSecretKeys is the case-insensitive key blocklist of the default redactor. It errs toward
// over-redaction.
var seededSecretKeys = map[string]struct{}{
	"password":      {},
	"secret":        {},
	"token":         {},
	"code":          {},
	"refresh_token": {},
	"access_token":  {},
}

// SeededSecretKeys returns a copy of the blocklist, for callers building their own redactor.
func SeededSecretKeys() []string {
	out := make([]string, 0, len(seededSecretKeys))
	for k := range seededSecretKeys {
		out = append(out, k)
	}
	return out
}

// DefaultRedactor masks values under secret-flavored keys (password, secret, token, code,
// refresh_token, access_token) at any depth, in place, and returns the same map. A custom
// Config.Audit.Redactor runs first and may strip more.
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

// isSecretKey reports whether k matches the blocklist, case-insensitively. EqualFold avoids a
// per-call allocation.
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

// HashEmailForAudit returns the hex sha256 of the lowercased email, so rows can be correlated by
// email without storing it.
func HashEmailForAudit(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}
