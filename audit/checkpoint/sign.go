package checkpoint

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// Ed25519Signer signs with an in-process Ed25519 private key.
type Ed25519Signer struct {
	keyID string
	key   ed25519.PrivateKey
}

// NewEd25519Signer builds a signer from a private key.
func NewEd25519Signer(key ed25519.PrivateKey, keyID string) (*Ed25519Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("checkpoint: invalid Ed25519 private key")
	}
	return &Ed25519Signer{keyID: keyID, key: key}, nil
}

// KeyID implements Signer.
func (s *Ed25519Signer) KeyID() string { return s.keyID }

// Sign implements Signer.
func (s *Ed25519Signer) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.key, message), nil
}

// PublicKey returns the verification key published under the signer's id.
func (s *Ed25519Signer) PublicKey() PublicKey {
	return NewPublicKey(s.keyID, s.key.Public().(ed25519.PublicKey))
}

// NewPublicKey wraps raw Ed25519 public key bytes as a PublicKey.
func NewPublicKey(keyID string, pub ed25519.PublicKey) PublicKey {
	return PublicKey{KeyID: keyID, PublicKey: JWK{Kty: jwkKty, Crv: jwkCrv, X: base64.RawURLEncoding.EncodeToString(pub)}}
}

// GenerateKeyPair makes a fresh Ed25519 key pair for signing checkpoints.
func GenerateKeyPair(keyID string) (*Ed25519Signer, PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, PublicKey{}, fmt.Errorf("checkpoint: generate key: %w", err)
	}
	s, err := NewEd25519Signer(priv, keyID)
	if err != nil {
		return nil, PublicKey{}, err
	}
	return s, NewPublicKey(keyID, pub), nil
}

// signedBytes is the exact message that is signed.
func signedBytes(c Checkpoint) ([]byte, error) {
	body := map[string]any{
		"version": c.Version, "alg": c.Alg, "keyId": c.KeyID, "size": c.Size,
		"rootHash": c.RootHash, "timestamp": c.Timestamp, "since": nilable(c.Since), "until": nilable(c.Until),
	}
	s, err := CanonicalJSON(body)
	if err != nil {
		return nil, err
	}
	return []byte(signDomain + s), nil
}

func nilable(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// signCheckpoint fills in Signature using signer.
func signCheckpoint(signer Signer, c Checkpoint) (Checkpoint, error) {
	msg, err := signedBytes(c)
	if err != nil {
		return Checkpoint{}, err
	}
	sig, err := signer.Sign(msg)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("checkpoint: sign: %w", err)
	}
	if len(sig) != signatureBytes {
		return Checkpoint{}, errors.New("checkpoint: signer did not return a 64 byte Ed25519 signature")
	}
	c.Signature = base64.RawURLEncoding.EncodeToString(sig)
	return c, nil
}

func validTime(p *int64) bool { return p == nil || (*p >= 0 && *p <= maxSafeInteger) }

// wellFormed is the shape check. It says nothing about the signature.
func wellFormed(c Checkpoint) bool {
	return c.Version == checkpointVersion && c.Size >= 0 && c.Size <= maxSafeInteger &&
		isHashHex(c.RootHash) && c.Timestamp >= 0 && c.Timestamp <= maxSafeInteger &&
		validTime(c.Since) && validTime(c.Until)
}

// VerifyCheckpoint verifies a checkpoint signature. It rejects any algorithm other than Ed25519 and
// any keyId no supplied key carries, so a checkpoint cannot choose its own key or algorithm.
func VerifyCheckpoint(c Checkpoint, keys ...PublicKey) Outcome {
	if !wellFormed(c) {
		return fail(ReasonMalformed)
	}
	if c.Alg != algEd25519 {
		return fail(ReasonUnsupportedAlg)
	}
	msg, err := signedBytes(c)
	if err != nil {
		return fail(ReasonMalformed)
	}
	return verifySignature(c.KeyID, c.Signature, msg, keys)
}

// verifySignature checks an Ed25519 signature made by the key published under keyID.
func verifySignature(keyID, signature string, msg []byte, keys []PublicKey) Outcome {
	var match *PublicKey
	for i := range keys {
		if subtle.ConstantTimeCompare([]byte(keys[i].KeyID), []byte(keyID)) == 1 {
			match = &keys[i]
			break
		}
	}
	if match == nil {
		return fail(ReasonUnknownKey)
	}
	if match.PublicKey.Kty != jwkKty || match.PublicKey.Crv != jwkCrv {
		return fail(ReasonUnsupportedAlg)
	}
	pub, err := base64.RawURLEncoding.Strict().DecodeString(match.PublicKey.X)
	if err != nil || len(pub) != publicKeyBytes {
		return fail(ReasonBadSignature)
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil || len(sig) != signatureBytes {
		return fail(ReasonBadSignature)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return fail(ReasonBadSignature)
	}
	return OK()
}
