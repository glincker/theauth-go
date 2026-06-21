package theauth

import "encoding/base64"

// base64StdEnc is a thin alias kept in its own file so importers of
// encoding/base64 stay scoped to where they are actually used (the v0.7
// SAML SP and SCIM endpoints).
func base64StdEnc(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
