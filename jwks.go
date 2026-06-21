package theauth

import (
	"context"
	"crypto/ed25519"
)

// jwks.go: thin forwarders for the JWKS rotation and JWT signing key
// surface. PR B architecture reorg (2026-06-20) moved the JWKS state
// machine and the Ed25519 keypair lifecycle into internal/as; the
// methods here keep the v2.0 *TheAuth receivers so callers in this
// package (handlers_oauth_server.go, service_token.go, etc.) compile
// unchanged. The forwarder calls go through directly; the underlying
// *as.Service handles the nil case (returns "authorization server not
// configured") so the wire behavior is identical to the pre-PR-B
// implementation.

// currentSigningKey returns the active (state = current) JWKS row and
// the decrypted private key. Used at every JWT mint.
func (a *TheAuth) currentSigningKey() (JWKSKey, ed25519.PrivateKey, error) {
	return a.as.CurrentSigningKey()
}

// publicKeyByKID returns the Ed25519 public key for the supplied kid,
// used at verify time. Returns false when the kid is unknown or
// retired.
func (a *TheAuth) publicKeyByKID(kid string) (ed25519.PublicKey, bool) {
	return a.as.PublicKeyByKID(kid)
}

// renderJWKSDoc removed in PR F when handlers_oauth_server.go moved
// into internal/as/handlers, which calls a.as.RenderJWKSDoc directly.

// RotateSigningKey advances the JWKS state machine one step: previous
// (if any) is retired, current becomes previous, next becomes current,
// and a fresh next is minted. Idempotent under concurrent callers (each
// call mints one fresh next). Operators can invoke this on emergency
// without waiting for the scheduled tick.
func (a *TheAuth) RotateSigningKey(ctx context.Context) error {
	return a.as.RotateSigningKey(ctx)
}
