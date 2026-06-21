package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// codeVerifierBytes is the number of random bytes used to build a PKCE code
// verifier. 32 bytes -> 43 base64url-no-pad chars, which is the minimum
// length permitted by RFC 7636 section 4.1 and the recommended default.
const codeVerifierBytes = 32

// NewCodeVerifier returns a fresh PKCE code verifier suitable for an
// authorization code exchange per RFC 7636. The result is 43 base64url
// (no-pad) characters of cryptographically random data, which sits at the
// low end of the [43,128] legal range.
func NewCodeVerifier() (string, error) {
	b := make([]byte, codeVerifierBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CodeChallenge derives the S256 code challenge from a verifier per RFC 7636
// section 4.2: challenge = base64url(sha256(ASCII(verifier))), no padding.
// Callers send this value as code_challenge with code_challenge_method=S256
// on the authorize request, then send the original verifier as code_verifier
// on the token exchange. The provider recomputes and compares.
func CodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
