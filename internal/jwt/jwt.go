// Package jwt implements the JWT surface the authorization server needs: Ed25519 (EdDSA) signing
// and verification of RFC 9068 access tokens (typ "at+jwt"), plus the RFC 7519 registered claims.
// It has no third-party dependency, and any alg other than EdDSA is rejected at parse time.
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

// Claims holds the RFC 7519 registered claims and the OAuth fields the AS uses. aud accepts a
// string; resource servers compare it against their identifier.
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
	// Extra holds non-registered claims. They are marshalled at top level by MarshalJSON, and carry
	// the act chain and delegation_grant_id.
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
	return signPayload(claims, TypeAccessToken, kid, priv)
}

// TypeLogoutToken is the typ header value for OIDC Back-Channel Logout
// tokens (OpenID Connect Back-Channel Logout 1.0 section 2.4).
const TypeLogoutToken = "logout+jwt"

// SignPayload signs an arbitrary JSON payload with an explicit typ. The back-channel logout token
// uses it, since its claims do not fit Claims.
func SignPayload(payload map[string]any, typ, kid string, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("jwt: ed25519 private key has wrong length")
	}
	return signPayload(payload, typ, kid, priv)
}

func signPayload(payload any, typ, kid string, priv ed25519.PrivateKey) (string, error) {
	header := Header{Alg: AlgEdDSA, Typ: typ, Kid: kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ResolveKey returns the public key for a kid from the token header. Implementations usually
// consult the JWKS snapshot.
type ResolveKey func(kid string) (ed25519.PublicKey, bool)

// Verify parses and authenticates a compact JWT. It fails on malformed input, an unsupported alg or
// typ, an unknown kid, a bad signature, an expired token or a token not yet valid. A non-empty
// expectedAud must match. The typ must be "at+jwt" (RFC 9068), so other JWTs signed by the same key
// cannot pass as access tokens. VerifyOpts with AllowMissingTyp is the tolerant mode.
func Verify(token string, resolve ResolveKey, expectedAud string, now time.Time) (Claims, error) {
	return VerifyOpts(token, resolve, expectedAud, now, VerifyOptions{})
}

// VerifyOptions tunes VerifyOpts.
type VerifyOptions struct {
	// AllowMissingTyp accepts a header with no typ, for tokens minted before typ was always set. A
	// different typ is still rejected.
	AllowMissingTyp bool
	// Skew is the clock tolerance on exp and nbf. A token counts as expired only after exp+Skew, and
	// not yet valid before nbf-Skew.
	Skew time.Duration
	// IgnoreExpiry skips the exp check. Only VerifyWith honours it; used for
	// id_token_hint, which RPs may legitimately present after expiry.
	IgnoreExpiry bool
}

// VerifyOpts is Verify with explicit options.
func VerifyOpts(token string, resolve ResolveKey, expectedAud string, now time.Time, opts VerifyOptions) (Claims, error) {
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
	if h.Typ == "" && !opts.AllowMissingTyp {
		return Claims{}, errors.New("jwt: header missing typ")
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

// PeekHeader parses the header without verifying the signature. The introspection cache uses it to
// read kid and jti for keys.
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
