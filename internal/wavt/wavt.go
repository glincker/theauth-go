// Package wavt is the WebAuthn virtual test helper used to drive the v0.5
// passkey ceremony tests. It is intentionally internal: external consumers
// should not depend on these helpers, both because the surface is unstable
// (it tracks our own service implementation, not the WebAuthn spec) and
// because a real authenticator emulator would dwarf the test surface this
// helper actually needs.
//
// What wavt provides:
//
//   - A tiny in-memory authenticator (Ed25519 keypair, random AAGUID) used
//     to assert that our challenge bookkeeping and storage replay guards
//     behave correctly without round-tripping a real CTAP2 attestation.
//   - Helpers to mint and re-use the in-memory webauthnChallenge entries
//     directly so service-level tests can target failure paths (expired,
//     reused, cross-user) without going through the browser handshake.
//
// What wavt does NOT provide:
//
//   - A full CTAP2 / WebAuthn L3 emulator capable of producing a valid
//     attestation object the upstream library will accept end-to-end.
//     The handlers' happy path is covered by the consumer example apps
//     (examples/webauthn-passkey) and by manual browser testing.
package wavt

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
)

// Authenticator is a minimal in-memory pretend authenticator. It owns a
// keypair and an AAGUID so tests can construct WebAuthnCredential rows
// whose fields look plausible end-to-end (16 byte AAGUID, non-empty public
// key) without doing real CBOR encoding.
type Authenticator struct {
	AAGUID [16]byte
	Pub    ed25519.PublicKey
	Priv   ed25519.PrivateKey
}

// NewAuthenticator returns a fresh in-memory authenticator seeded from
// crypto/rand. Returns an error only on RNG failure (vanishingly rare).
func NewAuthenticator() (*Authenticator, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var aaguid [16]byte
	if _, err := io.ReadFull(rand.Reader, aaguid[:]); err != nil {
		return nil, err
	}
	return &Authenticator{AAGUID: aaguid, Pub: pub, Priv: priv}, nil
}

// FakeCredentialID returns a random N-byte credential id for tests that
// only need an opaque, unique identifier (no real attestation).
func FakeCredentialID(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// FakePublicKeyBytes returns a deterministic byte slice meant to stand in
// for the COSE_Key public-key blob in storage layer tests. It is NOT a
// valid COSE encoding; callers must not feed it back into the upstream
// library's verify paths.
func (a *Authenticator) FakePublicKeyBytes() []byte {
	out := make([]byte, len(a.Pub))
	copy(out, a.Pub)
	return out
}
