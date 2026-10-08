package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	phc, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected PHC prefix: %q", phc)
	}
	ok, err := VerifyPassword("correct horse battery staple", phc)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected verify=true on round trip")
	}
}

func TestVerifyPasswordWrongPasswordFails(t *testing.T) {
	phc, err := HashPassword("right-password-xyz")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword("wrong-password-xyz", phc)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected verify=false for wrong password")
	}
}

func TestVerifyPasswordMalformedPHC(t *testing.T) {
	cases := []string{
		"",
		"not-a-phc-string",
		"$argon2id$v=19$bad",
		"$bcrypt$v=2$cost=10$saltsalt$hashhash",
		"$argon2id$v=99$m=65536,t=3,p=4$c2FsdA$aGFzaA", // bad version
		"$argon2id$v=19$m=bad,t=3,p=4$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=4$!!!notbase64$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$!!!notbase64",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			ok, err := VerifyPassword("whatever", c)
			if ok {
				t.Fatal("ok should be false on malformed PHC")
			}
			if !errors.Is(err, ErrInvalidPasswordHash) {
				t.Fatalf("expected ErrInvalidPasswordHash, got %v", err)
			}
		})
	}
}

// Salt is random per call, two hashes of the same password must differ.
func TestHashPasswordUsesFreshSalt(t *testing.T) {
	a, err := HashPassword("same-password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword("same-password")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two hashes of the same password must differ (random salt)")
	}
	// Both must still verify against the original.
	for _, phc := range []string{a, b} {
		ok, err := VerifyPassword("same-password", phc)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("verify failed for %s", phc)
		}
	}
}

func TestRehashOnLoginForWeakArgon2Params(t *testing.T) {
	weak := func(plain string, mem, iters uint32, threads uint8) string {
		salt := []byte("0123456789abcdef")
		key := argon2.IDKey([]byte(plain), salt, iters, mem, threads, 32)
		enc := base64.RawStdEncoding.EncodeToString
		return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, mem, iters, threads, enc(salt), enc(key))
	}
	current, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		hash       string
		pw         string
		wantMatch  bool
		wantRehash bool
		wantNeeds  bool
	}{
		{"current params untouched", current, "pw", true, false, false},
		{"low memory upgraded", weak("pw", 8*1024, 3, 4), "pw", true, true, true},
		{"low time upgraded", weak("pw", 64*1024, 1, 4), "pw", true, true, true},
		{"wrong password never rehashes", weak("pw", 8*1024, 3, 4), "nope", false, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NeedsRehash(tc.hash); got != tc.wantNeeds {
				t.Fatalf("NeedsRehash=%v want %v", got, tc.wantNeeds)
			}
			ok, newHash, err := VerifyPasswordWithLegacyFallback(tc.pw, tc.hash, false)
			if err != nil || ok != tc.wantMatch {
				t.Fatalf("ok=%v err=%v want %v", ok, err, tc.wantMatch)
			}
			if (newHash != "") != tc.wantRehash {
				t.Fatalf("newHash=%q wantRehash=%v", newHash, tc.wantRehash)
			}
			if newHash != "" {
				if NeedsRehash(newHash) {
					t.Fatal("rehashed value still below baseline")
				}
				if ok, _ := VerifyPassword("pw", newHash); !ok {
					t.Fatal("rehashed value does not verify")
				}
			}
		})
	}
}
