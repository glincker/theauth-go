// Package saml holds the small SAML helpers that the root theauth package
// uses internally but does not export. Phase 1 of the architecture reorg
// (2026-06) moved the standard-encoding base64 helper here so that the
// encoding/base64 dependency is scoped to the SAML SP code paths that
// actually need it.
package saml

import "encoding/base64"

// StdEnc returns the standard base64 encoding of b. Used by the SAML SP
// when emitting raw certificate bytes inside the IdP-signed assertion
// envelope; standard encoding is required by the SAML XML signature
// canonicalisation rules. Equivalent to base64.StdEncoding.EncodeToString.
func StdEnc(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
