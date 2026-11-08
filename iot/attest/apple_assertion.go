package attest

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
)

// Apple App Attest assertions (Apple's "Validating apps that connect to your server", assertion
// steps), the Go twin of the TypeScript verifyAppleAssertion.
//
// An assertion proves a request came from the app instance whose key was attested at enrollment.
// The result of generateAssertion is a CBOR map {signature, authenticatorData}. The server hashes
// the client data, computes nonce = SHA-256(authenticatorData || clientDataHash), verifies the
// ECDSA signature (SHA-256) over nonce with the attested key, checks rpIdHash equals SHA-256(appId)
// and checks that the counter grew. Replay protection is the counter, which the caller must store
// atomically (see internal/as VerifyDeviceAppAssertion), plus a challenge inside the client data.

// AppleAssertionInput is one assertion to check.
type AppleAssertionInput struct {
	// Assertion is the assertion object, base64 or base64url of the CBOR map.
	Assertion string
	// ClientData is the exact bytes the app hashed to make clientDataHash.
	ClientData []byte
	// AppID is <TeamID>.<BundleID>.
	AppID string
	// PublicKey is the attested key as an X9.62 uncompressed point (65 bytes), base64 or base64url. It
	// is the attestedPublicKey claim of the App Attest verifier.
	PublicKey string
	// PreviousCounter is the highest counter accepted so far for the key, 0 right after attestation.
	PreviousCounter int64
}

// AppleAssertionResult is the verdict. Reason is the same sentence the TypeScript verifier returns.
type AppleAssertionResult struct {
	OK      bool
	Reason  string
	Counter uint32
	Flags   byte
}

// ReasonAssertionCounter is the refusal text of a counter that did not grow. Callers use it to tell a
// replay from a forged assertion.
const ReasonAssertionCounter = "Assertion counter did not increase"

// p256SPKIPrefix is the SubjectPublicKeyInfo header of an uncompressed P-256 key.
var p256SPKIPrefix = []byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00}

// VerifyAppleAssertion checks an assertion. A refusal is a Result with OK false, never an error.
func VerifyAppleAssertion(in AppleAssertionInput) AppleAssertionResult {
	fail := func(reason string) AppleAssertionResult { return AppleAssertionResult{Reason: reason} }
	if in.PreviousCounter < 0 || in.PreviousCounter > 0xffffffff {
		return fail("Stored counter is not valid")
	}
	raw, err := decodeBase64(in.Assertion)
	if err != nil {
		return fail("Assertion or key is not base64")
	}
	point, err := decodeBase64(in.PublicKey)
	if err != nil {
		return fail("Assertion or key is not base64")
	}
	if len(point) != 65 || point[0] != 4 {
		return fail("Public key is not an uncompressed P-256 point")
	}
	decoded, err := decodeCBORExact(raw)
	if err != nil {
		return fail("Assertion is not valid CBOR")
	}
	m, ok := decoded.(cborMap)
	if !ok {
		return fail("Assertion is not a CBOR map")
	}
	sigAny, _ := m.str("signature")
	authAny, _ := m.str("authenticatorData")
	sig, ok1 := sigAny.([]byte)
	auth, ok2 := authAny.([]byte)
	if !ok1 || !ok2 {
		return fail("Assertion needs signature and authenticatorData")
	}
	// rpIdHash (32) + flags (1) + counter (4). Apple may append extension bytes after the counter,
	// the signature covers them.
	if len(auth) < 37 {
		return fail("authenticatorData is too short")
	}
	if !constantTimeEqual(auth[:32], sha256Sum([]byte(in.AppID))) {
		return fail("Assertion is not for this App ID")
	}
	counter := binary.BigEndian.Uint32(auth[33:37])
	clientDataHash := sha256Sum(in.ClientData)
	nonce := sha256Sum(concat(auth, clientDataHash))
	pub, err := x509.ParsePKIXPublicKey(concat(p256SPKIPrefix, point))
	key, isEC := pub.(*ecdsa.PublicKey)
	if err != nil || !isEC {
		return fail("Assertion signature is not valid")
	}
	// ECDSA over SHA-256(nonce): Apple signs the nonce as the message, so it is hashed once more.
	r, sInt, err := ecdsaDERToInts(sig, 32)
	if err != nil || !ecdsa.Verify(key, sha256Sum(nonce), r, sInt) {
		return fail("Assertion signature is not valid")
	}
	// Checked after the signature so an unsigned counter never decides anything.
	if int64(counter) <= in.PreviousCounter {
		return fail(ReasonAssertionCounter)
	}
	return AppleAssertionResult{OK: true, Counter: counter, Flags: auth[32]}
}

func (r AppleAssertionResult) String() string {
	if r.OK {
		return fmt.Sprintf("ok counter=%d", r.Counter)
	}
	return "refused: " + r.Reason
}
