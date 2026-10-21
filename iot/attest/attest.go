package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// Input is what a verifier receives for one enrollment. It matches the TypeScript
// DeviceAttestationInput field for field.
type Input struct {
	// Evidence is the raw evidence from the device, a JSON document whose shape depends on the verifier.
	Evidence string
	// Nonce is the server issued enrollment nonce the device says it used. Every verifier here
	// refuses an empty nonce: evidence that cannot be shown fresh is never accepted.
	Nonce string
	// HardwareID is the identifier the device reports, if any. The built in verifiers do not match it.
	HardwareID   string
	EnrollmentID string
	// CredentialKind is the kind of credential the device enrolls: "psk", "jwk" or "x509".
	CredentialKind string
	// CredentialKeyThumbprint is the RFC 7638 SHA-256 thumbprint of the enrolled public key when
	// CredentialKind is "jwk".
	CredentialKeyThumbprint string
	// ActivationKey is the server secret behind the TPM credential activation (see
	// DeriveActivationSecret). Enrollment sets it for the TPM certify verifier, which refuses without it.
	ActivationKey []byte
}

// Result is a verifier's decision. On refusal Reason is a short, stable sentence that is the same
// text the TypeScript verifiers return. On success Claims holds the verified facts, with the same
// keys and values as the TypeScript claims, and is stored with the device by the caller.
type Result struct {
	OK     bool
	Reason string
	Claims map[string]any
}

// Verifier checks attestation evidence. A refusal is a Result with OK false and a nil error. The
// error return is for failures that are not about the evidence, such as a revocation list that
// cannot be fetched, and callers must treat a non nil error as a refusal.
type Verifier func(ctx context.Context, in Input) (Result, error)

// reasonError is an error whose text is a refusal sentence shared with the TypeScript verifiers,
// so it starts with a capital letter.
type reasonError struct{ msg string }

func (e *reasonError) Error() string { return e.msg }

func reasonErr(msg string) error { return &reasonError{msg: msg} }

func fail(reason string) (Result, error) { return Result{Reason: reason}, nil }

// ChallengeEncoding says how the device turned the nonce string into the bytes it put into the
// attestation challenge.
type ChallengeEncoding string

// Challenge encodings. The empty value means ChallengeUTF8.
const (
	ChallengeUTF8      ChallengeEncoding = "utf8"
	ChallengeBase64URL ChallengeEncoding = "base64url"
	ChallengeHex       ChallengeEncoding = "hex"
)

func (e ChallengeEncoding) valid() bool {
	switch e {
	case "", ChallengeUTF8, ChallengeBase64URL, ChallengeHex:
		return true
	}
	return false
}

func (e ChallengeEncoding) encode(nonce string) ([]byte, error) {
	switch e {
	case ChallengeHex:
		return hex.DecodeString(nonce)
	case ChallengeBase64URL:
		return decodeBase64(nonce)
	}
	return []byte(nonce), nil
}

// Bool returns a pointer to b, for the options whose default is true.
func Bool(b bool) *bool { return &b }

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func clock(f func() time.Time) time.Time {
	if f != nil {
		return f()
	}
	return time.Now()
}

func constantTimeEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

func sha256Sum(data []byte) []byte {
	s := sha256.Sum256(data)
	return s[:]
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// keyThumbprint returns the RFC 7638 SHA-256 thumbprint of an EC P-256 or P-384
// SubjectPublicKeyInfo, or "" for anything else.
func keyThumbprint(spki []byte) string {
	info, err := spkiInfo(spki)
	if err != nil || info.alg != oidECPublicKey {
		return ""
	}
	var crv string
	var size int
	switch info.curve {
	case oidCurveP384:
		crv, size = "P-384", 48
	case oidCurveP256:
		crv, size = "P-256", 32
	default:
		return ""
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return ""
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve == nil || (crv == "P-256" && key.Curve != elliptic.P256()) || (crv == "P-384" && key.Curve != elliptic.P384()) {
		return ""
	}
	x := base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, size)))
	y := base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, size)))
	canonical := fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, crv, x, y)
	return base64.RawURLEncoding.EncodeToString(sha256Sum([]byte(canonical)))
}
