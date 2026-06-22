// Package dpop implements RFC 9449 Demonstrating Proof-of-Possession
// (DPoP) for OAuth 2.0 / OAuth 2.1 sender-constrained access tokens.
//
// The authorization server uses this package to:
//
//  1. Verify the DPoP proof JWT that accompanies a token request.
//  2. Compute the RFC 7638 JWK thumbprint of the client's public key.
//  3. Embed an RFC 7800 confirmation claim (cnf.jkt) in the issued access
//     token, binding the token to the proof key.
//  4. Issue + verify short-lived DPoP-Nonce values when the operator wants
//     nonce-gated proofs (RFC 9449 section 8).
//
// Resource servers reuse the same proof verifier to confirm every incoming
// request: a stolen access token is useless without the holder's private
// key, because the proof JWT covers the request method, URL, and a hash of
// the access token (ath claim).
//
// Algorithms supported: ES256, ES384, RS256, PS256, and EdDSA. The set is
// configurable; only the asymmetric algorithms listed in RFC 9449 section
// 4.2 are eligible (HS* and "none" are unconditionally rejected to defend
// against algorithm confusion).
//
// The package is dependency-free apart from the Go standard library so the
// mcpresource module can reuse it without picking up new transitive deps.
package dpop

import (
	"crypto/sha256"
	"encoding/base64"
)

// Confirmation is the RFC 7800 cnf claim payload embedded in DPoP-bound
// access tokens. Only the jkt (JWK thumbprint) member is populated; future
// confirmation methods (mTLS x5t#S256, kid) can land here additively.
type Confirmation struct {
	JKT string `json:"jkt"`
}

// NewConfirmation returns the cnf payload for a DPoP-bound access token.
// The supplied thumbprint must be the RFC 7638 SHA-256 thumbprint of the
// public key from the DPoP proof header, base64url-encoded without padding.
func NewConfirmation(jkt string) Confirmation {
	return Confirmation{JKT: jkt}
}

// AccessTokenHash returns the RFC 9449 section 4.2 "ath" value for the
// supplied access token: base64url(SHA-256(access_token)). Callers compare
// this against the ath claim carried in a DPoP proof to confirm the proof
// is bound to the presented access token (not a different one captured
// elsewhere).
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
