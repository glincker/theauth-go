package as

import "crypto/ed25519"

// verifyEd25519Impl wraps crypto/ed25519.Verify in its own file, so the dependency stays visible.
func verifyEd25519Impl(pub []byte, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
