// Package jwt implements the minimum JWT surface required by the v2.0
// authorization server: Ed25519 (EdDSA) sign and verify for access tokens
// shaped per RFC 9068 (typ = "at+jwt"). Header carries alg + kid + typ; the
// payload is encoded application-specific Claims plus required RFC 7519
// registered claims.
//
// This package is deliberately small and dependency free; it does not import
// any third-party JWT library. Algorithm confusion attacks are mitigated by
// rejecting any alg other than EdDSA at parse time.
package jwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Algorithm string emitted in the JOSE header. Phase 1 + 2 supports EdDSA
// only; RS256 lands in a later phase per the v2.0 design.
const AlgEdDSA = "EdDSA"

// TypeAccessToken is the typ value mandated by RFC 9068 for OAuth 2.0 access
// tokens encoded as JWTs.
const TypeAccessToken = "at+jwt"

// Header is the JOSE header for an access token JWT.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Claims captures the RFC 7519 registered claims plus the OAuth 2.0
// application-specific fields used by the v2.0 AS. The aud claim accepts a
// string for compatibility; resource servers compare against the configured
// resource identifier.
type Claims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Nbf      int64  `json:"nbf,omitempty"`
	Jti      string `json:"jti"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	Typ      string `json:"typ,omitempty"`
	// Extra carries non-registered claims. Marshalled at top level via the
	// custom MarshalJSON below. Phase 3+ uses this for the act chain and
	// delegation_grant_id.
	Extra map[string]any `json:"-"`
}

// MarshalJSON flattens Extra into the same JSON object as the registered
// claims, dropping any key collision (registered fields win).
func (c Claims) MarshalJSON() ([]byte, error) {
	type alias Claims
	base, err := json.Marshal(alias(c))
	if err != nil {
		return nil, err
	}
	if len(c.Extra) == 0 {
		return base, nil
	}
	var registered map[string]any
	if err := json.Unmarshal(base, &registered); err != nil {
		return nil, err
	}
	for k, v := range c.Extra {
		if _, exists := registered[k]; exists {
			continue
		}
		registered[k] = v
	}
	return json.Marshal(registered)
}

// UnmarshalJSON parses a Claims, capturing unknown top-level fields into
// Extra. Required so verifiers can read the act chain in a later phase.
func (c *Claims) UnmarshalJSON(data []byte) error {
	type alias Claims
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*c = Claims(a)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	registered := map[string]struct{}{
		"iss": {}, "sub": {}, "aud": {}, "exp": {}, "iat": {}, "nbf": {},
		"jti": {}, "client_id": {}, "scope": {}, "typ": {},
	}
	for k, v := range raw {
		if _, ok := registered[k]; ok {
			continue
		}
		var anyV any
		if err := json.Unmarshal(v, &anyV); err != nil {
			continue
		}
		if c.Extra == nil {
			c.Extra = map[string]any{}
		}
		c.Extra[k] = anyV
	}
	return nil
}

// Sign produces a compact-serialized EdDSA JWT for the supplied claims. The
// kid identifies the signing key in the JWKS document.
func Sign(claims Claims, kid string, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("jwt: ed25519 private key has wrong length")
	}
	header := Header{Alg: AlgEdDSA, Typ: TypeAccessToken, Kid: kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ResolveKey is the verifier-side callback that returns the public key matching
// the kid embedded in a token header. Implementations typically consult the
// JWKS snapshot.
type ResolveKey func(kid string) (ed25519.PublicKey, bool)

// Verify parses and authenticates a compact JWT. Returns the parsed claims
// on success; returns an error for any of:
//   - malformed encoding (not three segments, bad base64);
//   - unsupported alg or typ in the header;
//   - unknown kid (ResolveKey returns false);
//   - signature mismatch;
//   - expired token (exp <= now);
//   - not-yet-valid token (nbf > now when present).
//
// The expectedAud parameter is optional: when non-empty, a mismatch returns
// an error. Resource servers should always pass their configured identifier.
func Verify(token string, resolve ResolveKey, expectedAud string, now time.Time) (Claims, error) {
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
	if h.Alg != AlgEdDSA {
		return Claims{}, fmt.Errorf("jwt: unsupported alg %q", h.Alg)
	}
	if h.Typ != "" && h.Typ != TypeAccessToken {
		return Claims{}, fmt.Errorf("jwt: unsupported typ %q", h.Typ)
	}
	if h.Kid == "" {
		return Claims{}, errors.New("jwt: header missing kid")
	}
	pub, ok := resolve(h.Kid)
	if !ok {
		return Claims{}, fmt.Errorf("jwt: unknown kid %q", h.Kid)
	}
	if len(pub) != ed25519.PublicKeySize {
		return Claims{}, errors.New("jwt: public key has wrong length")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("jwt: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
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
	if c.Exp == 0 || time.Unix(c.Exp, 0).Before(now) {
		return Claims{}, errors.New("jwt: token expired")
	}
	if c.Nbf != 0 && time.Unix(c.Nbf, 0).After(now) {
		return Claims{}, errors.New("jwt: token not yet valid")
	}
	if expectedAud != "" && c.Aud != expectedAud {
		return Claims{}, fmt.Errorf("jwt: aud mismatch (got %q, want %q)", c.Aud, expectedAud)
	}
	return c, nil
}

// PeekHeader parses just the header segment without verifying the signature.
// Used by the introspection cache to extract kid + jti for cache keys without
// running a full Verify.
func PeekHeader(token string) (Header, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Header{}, errors.New("jwt: token must have three segments")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Header{}, err
	}
	var h Header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return Header{}, err
	}
	return h, nil
}
