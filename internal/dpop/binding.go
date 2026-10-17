// Package dpop implements RFC 9449 DPoP for sender-constrained tokens. The authorization server
// verifies proofs, computes the RFC 7638 thumbprint, and binds cnf.jkt into issued tokens. Resource
// servers reuse the verifier, so a stolen access token is useless without the holder's key. Only
// asymmetric algorithms are accepted (HS* and none are always rejected). The package depends only
// on the standard library so mcpresource can reuse it.
package dpop

import (
	"crypto/sha256"
	"encoding/base64"
)

// Confirmation is the RFC 7800 cnf payload of DPoP-bound access tokens. Only jkt is populated today.
type Confirmation struct {
	JKT string `json:"jkt"`
}

// NewConfirmation returns the cnf payload for a DPoP-bound token. The thumbprint is the RFC 7638
// SHA-256 thumbprint of the proof key.
func NewConfirmation(jkt string) Confirmation {
	return Confirmation{JKT: jkt}
}

// AccessTokenHash returns the RFC 9449 section 4.2 ath value, base64url(SHA-256(access_token)). It
// binds a proof to the presented token.
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
