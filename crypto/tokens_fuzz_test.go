package crypto_test

import (
	"bytes"
	"testing"

	"github.com/glincker/theauth-go/crypto"
)

// FuzzTokenHashRoundTrip asserts HashToken is deterministic, returns a
// fixed length digest (32 bytes for SHA-256), and never panics on empty
// or large input. Input is capped at 1 MiB to keep the corpus small.
func FuzzTokenHashRoundTrip(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("short"))
	f.Add(bytes.Repeat([]byte{0xa5}, 4096))

	f.Fuzz(func(t *testing.T, token []byte) {
		if len(token) > 1<<20 {
			token = token[:1<<20]
		}
		h1 := crypto.HashToken(string(token))
		h2 := crypto.HashToken(string(token))
		if len(h1) != 32 {
			t.Fatalf("HashToken returned %d bytes, want 32", len(h1))
		}
		if !bytes.Equal(h1, h2) {
			t.Fatalf("HashToken is non-deterministic")
		}
	})
}
