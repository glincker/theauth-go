package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestNewTokenIsURLSafeAndUnique(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("tokens must be unique")
	}
	if len(a) < 32 {
		t.Fatalf("token too short: %d", len(a))
	}
	// URL-safe base64 means no '+' '/' '='
	for _, c := range a {
		if c == '+' || c == '/' || c == '=' {
			t.Fatalf("token contains non-URL-safe char: %q", c)
		}
	}
}

func TestHashTokenIsStableSHA256(t *testing.T) {
	tok := "hello-world"
	got := HashToken(tok)
	want := sha256.Sum256([]byte(tok))
	if hex.EncodeToString(got) != hex.EncodeToString(want[:]) {
		t.Fatalf("got %x, want %x", got, want)
	}
}
