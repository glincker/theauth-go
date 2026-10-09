package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// multialg.go: algorithm-agile signing and verification for tokens minted by
// the authorization server. The original Sign and Verify entry points stay
// EdDSA only; the functions here add ES256 and RS256 so a client can be
// issued tokens its resource servers are able to verify.
//
// Algorithm confusion is closed by construction: VerifyWith resolves the key
// by kid, then requires the key type to match the alg named in the header.
// The "none" alg and HMAC algs are never accepted.

const (
	// AlgES256 is ECDSA over P-256 with SHA-256 (RFC 7518 section 3.4).
	AlgES256 = "ES256"
	// AlgRS256 is RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 section 3.3).
	AlgRS256 = "RS256"
	// TypeIDJAG is the JOSE typ of an Identity Assertion JWT Authorization
	// Grant (draft-ietf-oauth-identity-assertion-authz-grant).
	TypeIDJAG = "oauth-id-jag+jwt"
)

// SupportedAlg reports whether alg can be used to sign AS tokens.
func SupportedAlg(alg string) bool {
	switch alg {
	case AlgEdDSA, AlgES256, AlgRS256:
		return true
	}
	return false
}

// KeyResolver returns the algorithm and public key registered for kid.
type KeyResolver func(kid string) (alg string, pub crypto.PublicKey, ok bool)

// SignWith signs claims with an arbitrary supported algorithm. typ is the
// JOSE typ header (TypeAccessToken for access tokens).
func SignWith(claims Claims, typ, kid, alg string, signer crypto.Signer) (string, error) {
	if signer == nil {
		return "", errors.New("jwt: nil signer")
	}
	headerJSON, err := json.Marshal(Header{Alg: alg, Typ: typ, Kid: kid})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := signBytes(alg, signer, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func signBytes(alg string, signer crypto.Signer, msg []byte) ([]byte, error) {
	switch alg {
	case AlgEdDSA:
		if _, ok := signer.Public().(ed25519.PublicKey); !ok {
			return nil, errors.New("jwt: EdDSA requires an ed25519 key")
		}
		return signer.Sign(rand.Reader, msg, crypto.Hash(0))
	case AlgES256:
		pub, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, errors.New("jwt: ES256 requires a P-256 key")
		}
		digest := sha256.Sum256(msg)
		der, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return derToRaw(der, 32)
	case AlgRS256:
		if _, ok := signer.Public().(*rsa.PublicKey); !ok {
			return nil, errors.New("jwt: RS256 requires an RSA key")
		}
		digest := sha256.Sum256(msg)
		return signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	return nil, fmt.Errorf("jwt: unsupported alg %q", alg)
}

// derToRaw converts an ASN.1 DER ECDSA signature to the fixed-width R||S form
// JWS requires (RFC 7515 appendix A.3).
func derToRaw(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 {
		return nil, errors.New("jwt: malformed ecdsa signature")
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

// VerifyWith parses and authenticates a compact JWT signed with any supported
// algorithm. expectedTyp is the required JOSE typ (TypeAccessToken for access
// tokens); a missing or different typ is rejected. expectedAud is optional.
func VerifyWith(token string, resolve KeyResolver, expectedTyp, expectedAud string, now time.Time, opts VerifyOptions) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("jwt: token must have three segments")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("jwt: header decode: %w", err)
	}
	var h Header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return Claims{}, fmt.Errorf("jwt: header parse: %w", err)
	}
	if !SupportedAlg(h.Alg) {
		return Claims{}, fmt.Errorf("jwt: unsupported alg %q", h.Alg)
	}
	if h.Typ != expectedTyp && !(h.Typ == "" && opts.AllowMissingTyp) {
		return Claims{}, fmt.Errorf("jwt: unsupported typ %q", h.Typ)
	}
	if h.Kid == "" {
		return Claims{}, errors.New("jwt: header missing kid")
	}
	alg, pub, ok := resolve(h.Kid)
	if !ok {
		return Claims{}, fmt.Errorf("jwt: unknown kid %q", h.Kid)
	}
	if alg != h.Alg {
		return Claims{}, errors.New("jwt: alg does not match key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("jwt: signature decode: %w", err)
	}
	if !verifyBytes(alg, pub, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, errors.New("jwt: signature mismatch")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("jwt: payload decode: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(payloadBytes, &c); err != nil {
		return Claims{}, fmt.Errorf("jwt: payload parse: %w", err)
	}
	if c.Exp == 0 || time.Unix(c.Exp, 0).Add(opts.Skew).Before(now) {
		return Claims{}, errors.New("jwt: token expired")
	}
	if c.Nbf != 0 && time.Unix(c.Nbf, 0).Add(-opts.Skew).After(now) {
		return Claims{}, errors.New("jwt: token not yet valid")
	}
	if expectedAud != "" && c.Aud != expectedAud {
		return Claims{}, fmt.Errorf("jwt: aud mismatch (got %q, want %q)", c.Aud, expectedAud)
	}
	return c, nil
}

func verifyBytes(alg string, pub crypto.PublicKey, msg, sig []byte) bool {
	switch alg {
	case AlgEdDSA:
		k, ok := pub.(ed25519.PublicKey)
		return ok && len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig)
	case AlgES256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() || len(sig) != 64 {
			return false
		}
		digest := sha256.Sum256(msg)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(k, digest[:], r, s)
	case AlgRS256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		digest := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil
	}
	return false
}
