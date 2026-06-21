package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
)

// recoveryCodeBytes is the raw entropy per recovery code: 5 bytes from
// crypto/rand, hex-encoded to 10 lowercase characters (40 bits of entropy).
//
// Why 40 bits and not more: a recovery code is presented to a human, often
// hand-copied, sometimes printed. 10 hex chars is the sweet spot between
// "long enough that 2^40 brute-force is infeasible per single stolen row"
// and "short enough that a user will actually transcribe it correctly".
// Per the v0.5 design doc, this is what motivates salted SHA-256 (not
// Argon2id) for storage: with 40 bits of crypto/rand entropy, the salt
// already pushes precomputation out of reach without paying KDF latency.
const recoveryCodeBytes = 5

// recoveryCodeSaltLen is the per-code salt size that prefixes the stored hash.
// 16 bytes (128 bits) is the standard recommendation for password-style salts
// and is comfortably larger than necessary here.
const recoveryCodeSaltLen = 16

// GenerateRecoveryCode draws recoveryCodeBytes from crypto/rand and returns
// the lowercase hex encoding (10 chars). Returned errors propagate any RNG
// failure; callers should bail on the whole enrollment.
func GenerateRecoveryCode() (string, error) {
	b := make([]byte, recoveryCodeBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashRecoveryCode produces a 48-byte storage value laid out as
// salt(16) || sha256(salt || code)(32). The salt is per-code random, so two
// rows holding the same plaintext code produce different hashes. Pre-computed
// rainbow tables are defeated by the salt alone; the sha256 digest then sits
// behind a 2^40 brute-force barrier per row.
func HashRecoveryCode(code string) ([]byte, error) {
	salt := make([]byte, recoveryCodeSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(code))
	digest := h.Sum(nil)
	out := make([]byte, 0, recoveryCodeSaltLen+sha256.Size)
	out = append(out, salt...)
	out = append(out, digest...)
	return out, nil
}

// VerifyRecoveryCode re-hashes the supplied plaintext using the salt extracted
// from the stored value and compares in constant time. Returns false on any
// malformed input (including a stored value shorter than the salt prefix).
func VerifyRecoveryCode(stored []byte, code string) bool {
	if len(stored) != recoveryCodeSaltLen+sha256.Size {
		return false
	}
	salt := stored[:recoveryCodeSaltLen]
	want := stored[recoveryCodeSaltLen:]
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(code))
	got := h.Sum(nil)
	return subtle.ConstantTimeCompare(got, want) == 1
}
