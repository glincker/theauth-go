package crypto_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/glincker/theauth-go/crypto"
)

// FuzzEncryptDecrypt asserts the round trip invariant
// Decrypt(key, Encrypt(key, pt)) == pt for any plaintext and any input key
// (the key is normalized to 32 bytes via SHA-256 expansion). The fuzzer
// must never panic and Encrypt followed by Decrypt must always succeed
// with a byte-identical plaintext.
func FuzzEncryptDecrypt(f *testing.F) {
	f.Add([]byte("seed-key"), []byte(""))
	f.Add([]byte("another-key"), []byte("hello, theauth"))
	f.Add(bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0x00}, 1024))

	f.Fuzz(func(t *testing.T, rawKey, plaintext []byte) {
		// Cap input size so the fuzz corpus stays manageable.
		if len(plaintext) > 64*1024 {
			plaintext = plaintext[:64*1024]
		}
		sum := sha256.Sum256(rawKey)
		key := sum[:]
		ct, err := crypto.Encrypt(key, plaintext)
		if err != nil {
			t.Fatalf("Encrypt returned error for normalized 32 byte key: %v", err)
		}
		got, err := crypto.Decrypt(key, ct)
		if err != nil {
			t.Fatalf("Decrypt round trip failed: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip mismatch: got %d bytes, want %d bytes", len(got), len(plaintext))
		}
	})
}

// FuzzDecryptArbitrary feeds arbitrary bytes into Decrypt with a fixed
// 32 byte key. The invariant is "never panic" and "any input shorter
// than nonce plus tag (28 bytes) or with a bad tag returns an error".
func FuzzDecryptArbitrary(f *testing.F) {
	f.Add([]byte(""))
	f.Add(bytes.Repeat([]byte{0}, 12))
	f.Add(bytes.Repeat([]byte{0xab}, 64))

	key := bytes.Repeat([]byte{0x42}, crypto.AESKeyLen)

	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		if len(ciphertext) > 64*1024 {
			ciphertext = ciphertext[:64*1024]
		}
		_, err := crypto.Decrypt(key, ciphertext)
		if len(ciphertext) < 12+16 && err == nil {
			t.Fatalf("Decrypt accepted ciphertext shorter than nonce plus tag: len=%d", len(ciphertext))
		}
		// Any non-nil err is fine; panic would be caught by the runtime.
	})
}
