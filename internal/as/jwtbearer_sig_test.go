package as

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

// JOSE encodes ES256 and ES384 signatures as fixed-length R||S (RFC 7518
// section 3.4); the verifier must accept that alongside ASN.1 DER.
func TestVerifySigAcceptsJOSEFixedLengthECDSA(t *testing.T) {
	cases := []struct {
		alg   string
		curve elliptic.Curve
		size  int
		hash  func([]byte) []byte
	}{
		{"ES256", elliptic.P256(), 32, func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }},
		{"ES384", elliptic.P384(), 48, func(b []byte) []byte { s := sha512.Sum384(b); return s[:] }},
	}
	msg := []byte("header.payload")
	for _, tc := range cases {
		priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		digest := tc.hash(msg)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
		if err != nil {
			t.Fatal(err)
		}
		raw := make([]byte, 2*tc.size)
		r.FillBytes(raw[:tc.size])
		s.FillBytes(raw[tc.size:])
		der, err := ecdsa.SignASN1(rand.Reader, priv, digest)
		if err != nil {
			t.Fatal(err)
		}
		if !verifySig(tc.alg, &priv.PublicKey, msg, raw) {
			t.Errorf("%s: fixed-length R||S rejected", tc.alg)
		}
		if !verifySig(tc.alg, &priv.PublicKey, msg, der) {
			t.Errorf("%s: ASN.1 DER rejected", tc.alg)
		}
		raw[0] ^= 0xff
		if verifySig(tc.alg, &priv.PublicKey, msg, raw) {
			t.Errorf("%s: tampered signature accepted", tc.alg)
		}
	}
}
