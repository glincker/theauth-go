package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// AESKeyLen is the required key length in bytes for Encrypt/Decrypt (AES-256).
const AESKeyLen = 32

// ErrInvalidKeyLength is returned when the supplied key is not exactly AESKeyLen.
var ErrInvalidKeyLength = errors.New("theauth/crypto: encryption key must be 32 bytes")

// ErrCiphertextTooShort is returned when the supplied ciphertext is shorter
// than the GCM nonce, meaning it cannot be a valid Encrypt output.
var ErrCiphertextTooShort = errors.New("theauth/crypto: ciphertext too short")

// Encrypt seals plaintext with AES-256-GCM and returns nonce || ciphertext.
// The 12-byte nonce is generated from crypto/rand and prepended so that
// Decrypt can split it back out without out-of-band metadata. key must be
// exactly 32 bytes (AES-256); other lengths return ErrInvalidKeyLength.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != AESKeyLen {
		return nil, ErrInvalidKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Seal appends ciphertext to the dst slice (here: nonce), so the return
	// is laid out as nonce || ciphertext_with_tag, exactly what Decrypt expects.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt: it splits off the 12-byte nonce prefix, then
// authenticates and decrypts the remainder. Returns an error if the key is
// the wrong length, the ciphertext is too short, or the authentication tag
// fails (wrong key or tampered ciphertext).
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != AESKeyLen {
		return nil, ErrInvalidKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, ErrCiphertextTooShort
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
