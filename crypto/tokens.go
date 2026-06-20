package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// NewToken returns a 32-byte cryptographically random token, URL-safe-base64-encoded.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns sha256(token) as raw bytes — store this, never the token itself.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}
