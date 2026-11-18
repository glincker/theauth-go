//go:build theauth_noecdsa

package device

// keys_noecdsa.go stubs the ECDSA paths for -tags theauth_noecdsa: an Ed25519 only build. ES256 and
// ES384 keys, tokens and signers are refused as unsupported, so the server must sign bundles and
// revocation snapshots with EdDSA for such a device.

import (
	"crypto"
	"errors"
	"io"
)

func newECDSAPublicKey(string, crypto.PublicKey) (PublicKey, bool) { return PublicKey{}, false }

func ecdsaThumbprintInput(crypto.PublicKey) []byte { return nil }

func ecdsaJWK(crypto.PublicKey, map[string]any) {}

func ecdsaPublicKeyFromJWK(string, string, []byte, []byte) (PublicKey, error) {
	return PublicKey{}, errors.New("device: built without ECDSA (theauth_noecdsa)")
}

func ecdsaVerify(PublicKey, []byte, []byte) bool { return false }

func newECDSASigner(crypto.PrivateKey, io.Reader) (*Signer, bool, error) { return nil, false, nil }
