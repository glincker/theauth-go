package crypto_test

import (
	"encoding/base64"
	"testing"

	"github.com/glincker/theauth-go/crypto"
)

// FuzzVerifierToChallenge exercises CodeChallenge across arbitrary input
// bytes. The invariant is "never panic" and "output is always a 43 char
// base64 URL no-pad string" because the underlying SHA-256 digest is
// always 32 bytes which encodes to exactly 43 raw URL base64 chars.
func FuzzVerifierToChallenge(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
	f.Add([]byte("not~a~valid~pkce~verifier"))

	f.Fuzz(func(t *testing.T, verifier []byte) {
		if len(verifier) > 4096 {
			verifier = verifier[:4096]
		}
		got := crypto.CodeChallenge(string(verifier))
		if len(got) != 43 {
			t.Fatalf("CodeChallenge returned %d chars, want 43", len(got))
		}
		// The output must round trip through raw URL base64 decoding (32 byte digest).
		raw, err := base64.RawURLEncoding.DecodeString(got)
		if err != nil {
			t.Fatalf("CodeChallenge output is not raw URL base64: %v", err)
		}
		if len(raw) != 32 {
			t.Fatalf("decoded challenge is %d bytes, want 32", len(raw))
		}
	})
}

// FuzzGenerateCodeVerifier asserts NewCodeVerifier always returns a 43
// char base64 URL no-pad string and never panics regardless of how many
// times it runs under the fuzzer (acts as a stress test under -race).
func FuzzGenerateCodeVerifier(f *testing.F) {
	f.Add([]byte("ignored-seed"))

	f.Fuzz(func(t *testing.T, _ []byte) {
		v, err := crypto.NewCodeVerifier()
		if err != nil {
			t.Fatalf("NewCodeVerifier returned error: %v", err)
		}
		if len(v) != 43 {
			t.Fatalf("verifier length = %d, want 43", len(v))
		}
		if _, err := base64.RawURLEncoding.DecodeString(v); err != nil {
			t.Fatalf("verifier is not raw URL base64: %v", err)
		}
	})
}
