package mcpresource

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// claims is the parsed JWT payload. Only the fields the validator needs are
// declared here; unknown claims are captured in extras so the act chain can
// be lifted into the principal.
type claims struct {
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

	Act               *actorClaim `json:"act,omitempty"`
	DelegationGrantID string      `json:"delegation_grant_id,omitempty"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// verifyJWT performs the EdDSA signature check plus structural validation:
// segment count, alg, kid, expiry, nbf, iat, audience. Returns the parsed
// claims on success.
func verifyJWT(token, expectedAud string, resolve func(kid string) (ed25519.PublicKey, error), now time.Time, skew time.Duration) (*claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("mcpresource: token must have three segments")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("mcpresource: header decode: %w", err)
	}
	var h jwtHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, fmt.Errorf("mcpresource: header parse: %w", err)
	}
	if h.Alg != "EdDSA" {
		return nil, fmt.Errorf("mcpresource: unsupported alg %q", h.Alg)
	}
	if h.Typ != "" && h.Typ != "at+jwt" {
		return nil, fmt.Errorf("mcpresource: unsupported typ %q", h.Typ)
	}
	if h.Kid == "" {
		return nil, errors.New("mcpresource: token header missing kid")
	}
	pub, err := resolve(h.Kid)
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("mcpresource: resolved key has wrong length")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("mcpresource: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return nil, errors.New("mcpresource: signature mismatch")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("mcpresource: payload decode: %w", err)
	}
	var c claims
	if err := json.Unmarshal(payloadBytes, &c); err != nil {
		return nil, fmt.Errorf("mcpresource: payload parse: %w", err)
	}
	if c.Exp == 0 || time.Unix(c.Exp, 0).Before(now.Add(-skew)) {
		return nil, errors.New("mcpresource: token expired")
	}
	if c.Nbf != 0 && time.Unix(c.Nbf, 0).After(now.Add(skew)) {
		return nil, errors.New("mcpresource: token not yet valid")
	}
	if c.Iat != 0 && time.Unix(c.Iat, 0).After(now.Add(skew)) {
		return nil, errors.New("mcpresource: token iat in the future")
	}
	if expectedAud != "" && c.Aud != expectedAud {
		return nil, fmt.Errorf("mcpresource: aud mismatch (got %q, want %q)", c.Aud, expectedAud)
	}
	return &c, nil
}
