package crypto

import (
	"errors"
	"strings"
	"testing"
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
