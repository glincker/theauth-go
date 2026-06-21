package crypto_test

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/crypto"
)

func TestNewCodeVerifierLengthIsRFCCompliant(t *testing.T) {
	for i := 0; i < 100; i++ {
		v, err := crypto.NewCodeVerifier()
		if err != nil {
			t.Fatal(err)
		}
		// RFC 7636 section 4.1: 43-128 chars from the unreserved set
		// [A-Z][a-z][0-9]-._~. base64url-no-pad of 32 random bytes is
		// always 43 chars, which sits at the low end of the legal range.
		if len(v) < 43 || len(v) > 128 {
			t.Fatalf("verifier length %d outside RFC 7636 [43,128]", len(v))
		}
		// All chars must be in the unreserved set. base64url emits
		// [A-Za-z0-9_-] so this is automatic, but assert anyway to catch
		// accidental impl drift.
		for _, c := range v {
			ok := (c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') ||
				c == '-' || c == '.' || c == '_' || c == '~'
			if !ok {
				t.Fatalf("verifier contains illegal char %q in %q", c, v)
			}
		}
	}
}

func TestNewCodeVerifierIsRandom(t *testing.T) {
	a, err := crypto.NewCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.NewCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two verifiers were identical: %q", a)
	}
}

func TestCodeChallengeRFC7636Vector(t *testing.T) {
	// From RFC 7636 Appendix B:
	//   code_verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	//   code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := crypto.CodeChallenge(verifier); got != want {
		t.Fatalf("CodeChallenge(%q) = %q, want %q", verifier, got, want)
	}
}

func TestCodeChallengeMatchesSHA256(t *testing.T) {
	v, err := crypto.NewCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	want := base64.RawURLEncoding.EncodeToString(sha256Sum([]byte(v)))
	got := crypto.CodeChallenge(v)
	if got != want {
		t.Fatalf("CodeChallenge mismatch: got %q want %q", got, want)
	}
	// And: never padded
	if strings.Contains(got, "=") {
		t.Fatalf("CodeChallenge should be base64url no-pad, got %q", got)
	}
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
