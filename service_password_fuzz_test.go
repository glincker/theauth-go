package theauth_test

import (
	"testing"

	"github.com/glincker/theauth-go"
)

// FuzzEmailValidation drives arbitrary input strings through the email
// validator. The invariant is "never panic" across RFC 5322 edge cases
// such as quoted local parts, IDN punycode, very long local parts,
// embedded NULs, leading or trailing whitespace, and the literal "<>".
func FuzzEmailValidation(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("user@example.com"))
	f.Add([]byte("\"quoted local\"@example.com"))
	f.Add([]byte("not-an-email"))
	f.Add([]byte("<>"))
	f.Add([]byte("user@xn--bcher-kva.example"))
	f.Add([]byte("a@b"))
	f.Add([]byte("user\x00@example.com"))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			input = input[:4096]
		}
		_, _ = theauth.ValidateEmailForTest(string(input))
		// No assertion beyond "did not panic". Returning an error for
		// malformed input is the documented behavior and is fine.
	})
}
