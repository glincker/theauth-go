package crypto_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/glincker/theauth-go/crypto"
)

// newKey returns a random 32-byte AES-256 key for tests.
func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := newKey(t)
	plaintext := []byte("github access token: gho_abcdef123456")

	ct, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext must not equal plaintext")
	}
	// nonce (12) + ciphertext (>= len(plaintext))
	if len(ct) < 12+len(plaintext) {
		t.Fatalf("ciphertext too short: got %d, want at least %d", len(ct), 12+len(plaintext))
	}

	pt, err := crypto.Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestEncryptDecryptEmptyPlaintext(t *testing.T) {
	key := newKey(t)
	ct, err := crypto.Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	pt, err := crypto.Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if len(pt) != 0 {
		t.Fatalf("expected empty plaintext, got %q", pt)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	key := newKey(t)
	wrongKey := newKey(t)
	ct, err := crypto.Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Decrypt(wrongKey, ct); err == nil {
		t.Fatal("expected error decrypting with wrong key, got nil")
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	key := newKey(t)
	ct, err := crypto.Encrypt(key, []byte("very secret payload"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit deep inside the ciphertext (past the 12-byte nonce).
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := crypto.Decrypt(key, tampered); err == nil {
		t.Fatal("expected error decrypting tampered ciphertext, got nil")
	}
}

func TestEncryptInvalidKeyLength(t *testing.T) {
	for _, badLen := range []int{0, 1, 15, 31, 33, 64} {
		key := make([]byte, badLen)
		if _, err := crypto.Encrypt(key, []byte("x")); err == nil {
			t.Fatalf("expected error for key length %d, got nil", badLen)
		}
	}
}

func TestDecryptInvalidKeyLength(t *testing.T) {
	good := newKey(t)
	ct, err := crypto.Encrypt(good, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, badLen := range []int{0, 1, 15, 31, 33, 64} {
		key := make([]byte, badLen)
		if _, err := crypto.Decrypt(key, ct); err == nil {
			t.Fatalf("expected error for key length %d, got nil", badLen)
		}
	}
}

func TestDecryptShortCiphertextFails(t *testing.T) {
	key := newKey(t)
	// Anything shorter than the 12-byte nonce can't be decrypted.
	for _, badLen := range []int{0, 1, 11} {
		if _, err := crypto.Decrypt(key, make([]byte, badLen)); err == nil {
			t.Fatalf("expected error for ciphertext length %d, got nil", badLen)
		}
	}
}

func TestEncryptIsNonDeterministic(t *testing.T) {
	key := newKey(t)
	pt := []byte("same plaintext every time")
	a, err := crypto.Encrypt(key, pt)
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.Encrypt(key, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("encryption must produce a fresh nonce per call; got identical ciphertexts")
	}
}
