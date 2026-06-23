package as

import "crypto/ed25519"

// verifyEd25519Impl wraps crypto/ed25519.Verify. Kept in its own file so
// the import of crypto/ed25519 is isolated from jwtbearer.go (which imports
// internal/jwt; internal/jwt also imports crypto/ed25519, but Go handles
// duplicate imports fine -- this separation just keeps the dependency visible).
func verifyEd25519Impl(pub []byte, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
