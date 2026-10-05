// Package emailnorm canonicalizes email addresses so uniqueness checks and
// lookups agree regardless of case, surrounding whitespace, or Unicode
// compatibility forms.
package emailnorm

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// Normalizer canonicalizes addresses. The zero value trims and lowercases.
type Normalizer struct {
	// NFKC additionally folds Unicode compatibility forms (for example
	// fullwidth letters) before lowercasing.
	NFKC bool
}

// Normalize returns the canonical form of raw.
func (n Normalizer) Normalize(raw string) string {
	s := strings.TrimSpace(raw)
	if n.NFKC {
		s = norm.NFKC.String(s)
	}
	return strings.ToLower(s)
}

// LogRef returns a short stable pseudonym for an already-canonical address so
// log lines can be correlated without writing the address itself.
func LogRef(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])[:12]
}
