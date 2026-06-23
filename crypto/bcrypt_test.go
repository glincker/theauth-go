package crypto_test

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/glincker/theauth-go/crypto"
)

// knownBcryptHash is a bcrypt hash of "correct-horse-battery-staple" at cost 10.
// Generated once and hardcoded for reproducibility.
var knownBcryptHash string

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte("correct-horse-battery-staple"), 10)
	if err != nil {
		panic("bcrypt test setup: " + err.Error())
	}
	knownBcryptHash = string(h)
}

func TestIsBcryptHash(t *testing.T) {
	tests := []struct {
		hash string
		want bool
	}{
		{"$2b$10$abcdefghijklmnopqrstuuVGmtU0Oy2P5FIlkTGYhN7wTEQpI3qFi", true},
		{"$2a$12$someotherhash", true},
		{"$2x$10$someotherhash", true},
		{"$argon2id$v=19$m=65536,t=3,p=4$abc$def", false},
		{"", false},
		{"notahash", false},
	}
	for _, tc := range tests {
		if got := crypto.IsBcryptHash(tc.hash); got != tc.want {
			t.Errorf("IsBcryptHash(%q)=%v; want %v", tc.hash, got, tc.want)
		}
	}
}

func TestBcryptFallbackVerify(t *testing.T) {
	ok, err := crypto.VerifyLegacyBcrypt("correct-horse-battery-staple", knownBcryptHash)
	if err != nil {
		t.Fatalf("VerifyLegacyBcrypt (correct password): %v", err)
	}
	if !ok {
		t.Error("VerifyLegacyBcrypt returned false for correct password")
	}
}

func TestBcryptFallbackRejectsWrongPassword(t *testing.T) {
	ok, err := crypto.VerifyLegacyBcrypt("wrong-password", knownBcryptHash)
	if err != nil {
		t.Fatalf("VerifyLegacyBcrypt (wrong password): unexpected error: %v", err)
	}
	if ok {
		t.Error("VerifyLegacyBcrypt returned true for wrong password")
	}
}

func TestBcryptFallbackTriggersRehash(t *testing.T) {
	matched, newHash, err := crypto.VerifyPasswordWithLegacyFallback(
		"correct-horse-battery-staple", knownBcryptHash, true,
	)
	if err != nil {
		t.Fatalf("VerifyPasswordWithLegacyFallback: %v", err)
	}
	if !matched {
		t.Error("expected match=true for correct password + bcrypt hash")
	}
	if newHash == "" {
		t.Error("expected non-empty newHash after bcrypt fallback; got empty string")
	}
	// The new hash must be Argon2id, not bcrypt.
	if !strings.HasPrefix(newHash, "$argon2id$") {
		t.Errorf("newHash=%q; expected Argon2id hash ($argon2id$ prefix)", newHash)
	}
	// Verify the new hash is correct using the standard VerifyPassword.
	ok, err := crypto.VerifyPassword("correct-horse-battery-staple", newHash)
	if err != nil {
		t.Fatalf("VerifyPassword(new argon2id hash): %v", err)
	}
	if !ok {
		t.Error("re-hashed Argon2id hash does not verify against the original password")
	}
}

func TestBcryptFallbackDisabledWhenNotAllowed(t *testing.T) {
	matched, newHash, err := crypto.VerifyPasswordWithLegacyFallback(
		"correct-horse-battery-staple", knownBcryptHash, false,
	)
	if err == nil {
		t.Error("expected error when allowLegacy=false and bcrypt hash is given")
	}
	if matched {
		t.Error("expected matched=false when allowLegacy=false")
	}
	if newHash != "" {
		t.Error("expected empty newHash when allowLegacy=false")
	}
}

func TestVerifyPasswordWithLegacyFallbackArgon2Normal(t *testing.T) {
	// Standard Argon2id path must still work.
	argonHash, err := crypto.HashPassword("my-secret")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	matched, newHash, err := crypto.VerifyPasswordWithLegacyFallback("my-secret", argonHash, true)
	if err != nil {
		t.Fatalf("VerifyPasswordWithLegacyFallback (argon2): %v", err)
	}
	if !matched {
		t.Error("Argon2id path: expected match=true")
	}
	if newHash != "" {
		t.Errorf("Argon2id path: expected empty newHash; got %q", newHash)
	}
}
