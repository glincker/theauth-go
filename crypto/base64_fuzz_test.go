package crypto_test

import (
	"encoding/base64"
	"testing"
)

// FuzzBase64URLDecode wraps the base64 URL no-pad decode path used by
// the token helpers and cookie paths. The invariant is "never panic"
// and "either returns valid bytes or a typed error".
func FuzzBase64URLDecode(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("aGVsbG8"))
	f.Add([]byte("not=base64==stuff"))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 16*1024 {
			input = input[:16*1024]
		}
		out, err := base64.RawURLEncoding.DecodeString(string(input))
		if err == nil && out == nil {
			t.Fatal("decode returned nil slice with nil error")
		}
		_, _ = out, err
	})
}
