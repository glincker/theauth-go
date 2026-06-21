package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestGenerateRecoveryCodeShape pins the user-facing format: 10 hex chars,
// lowercase. 10 hex chars is 40 bits of entropy from crypto/rand, which is
// the documented design choice (see recoverycode.go).
func TestGenerateRecoveryCodeShape(t *testing.T) {
	code, err := GenerateRecoveryCode()
	if err != nil {
		t.Fatalf("GenerateRecoveryCode: %v", err)
	}
	if len(code) != 10 {
		t.Fatalf("recovery code length: got %d want 10", len(code))
	}
	if code != strings.ToLower(code) {
		t.Fatalf("recovery code must be lowercase, got %q", code)
	}
	if _, err := hex.DecodeString(code); err != nil {
		t.Fatalf("recovery code must be hex, got %q (%v)", code, err)
	}
}

// TestGenerateRecoveryCodeUniqueness verifies that 10 codes drawn in a row are
// all distinct. With 40 bits of entropy, collisions in 10 draws are astronomical;
// any collision here means the RNG is wired wrong.
func TestGenerateRecoveryCodeUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		c, err := GenerateRecoveryCode()
		if err != nil {
			t.Fatal(err)
		}
		if seen[c] {
			t.Fatalf("duplicate recovery code in 10 draws: %q", c)
		}
		seen[c] = true
	}
}

// TestHashRecoveryCodeLayout pins the storage layout: 16-byte salt prefix
// followed by 32-byte sha256 digest, totaling 48 bytes. Callers depend on
// this fixed shape for the bytea column.
func TestHashRecoveryCodeLayout(t *testing.T) {
	h, err := HashRecoveryCode("0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 16+32 {
		t.Fatalf("hash length: got %d want 48", len(h))
	}
}

// TestHashRecoveryCodeSaltsDiffer ensures two hashes of the same code use
// different salts (defeats rainbow tables across multiple rows).
func TestHashRecoveryCodeSaltsDiffer(t *testing.T) {
	h1, err := HashRecoveryCode("abcd012345")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashRecoveryCode("abcd012345")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(h1[:16], h2[:16]) {
		t.Fatalf("salts must differ across generations of the same plaintext")
	}
	if bytes.Equal(h1, h2) {
		t.Fatalf("full hashes must differ when salts differ")
	}
}

// TestVerifyRecoveryCodeRoundtrip checks the happy path: HashRecoveryCode then
// VerifyRecoveryCode with the same plaintext returns true.
func TestVerifyRecoveryCodeRoundtrip(t *testing.T) {
	code := "deadbeef00"
	h, err := HashRecoveryCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRecoveryCode(h, code) {
		t.Fatalf("verify should succeed for matching plaintext")
	}
}

// TestVerifyRecoveryCodeMismatch covers the negative path: a one-char delta
// must return false.
func TestVerifyRecoveryCodeMismatch(t *testing.T) {
	h, err := HashRecoveryCode("deadbeef00")
	if err != nil {
		t.Fatal(err)
	}
	if VerifyRecoveryCode(h, "deadbeef01") {
		t.Fatalf("verify must reject mutated plaintext")
	}
}

// TestVerifyRecoveryCodeMalformedHash guards against panics on stored data
// that is shorter than the 16-byte salt prefix.
func TestVerifyRecoveryCodeMalformedHash(t *testing.T) {
	short := make([]byte, 8) // shorter than salt
	if VerifyRecoveryCode(short, "anything00") {
		t.Fatalf("verify must return false on too-short hash")
	}
}
