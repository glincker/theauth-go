package mcpresource

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// claims is the parsed JWT payload. Only the fields the validator needs are
// declared here; unknown claims are captured in extras so the act chain can
// be lifted into the principal.
type claims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      audience `json:"aud"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	Nbf      int64    `json:"nbf,omitempty"`
	Jti      string   `json:"jti"`
	ClientID string   `json:"client_id"`
	Scope    string   `json:"scope"`
	Typ      string   `json:"typ,omitempty"`

	Act               *actorClaim `json:"act,omitempty"`
	DelegationGrantID string      `json:"delegation_grant_id,omitempty"`

	// Acr and AuthTime (OIDC core / RFC 9470) describe how and when the
	// user last authenticated; AuthTime is seconds since the epoch.
	Acr      string   `json:"acr,omitempty"`
	AuthTime int64    `json:"auth_time,omitempty"`
	Amr      []string `json:"amr,omitempty"`

	// AuthorizationDetails is the raw RFC 9396 array; parsed lazily into
	// the principal.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`

	// Cnf is the RFC 7800 confirmation claim. When the AS embedded a
	// cnf.jkt at token issuance time, the middleware REQUIRES an
	// inbound DPoP proof whose JWK thumbprint matches.
	Cnf *confirmationClaim `json:"cnf,omitempty"`
}

// confirmationClaim is the RFC 7800 cnf claim shape. Only the jkt
// member is observed today; future confirmation methods (mTLS, kid) can
// land here additively without breaking older callers.
type confirmationClaim struct {
	JKT string `json:"jkt,omitempty"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// audience holds the aud claim, which RFC 7519 section 4.1.3 allows to be
// either a single string or an array of strings.
type audience []string

// UnmarshalJSON accepts a JSON string or an array of strings.
func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("aud must be a string or an array of strings")
	}
	*a = audience(many)
	return nil
}

func (a audience) contains(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

// first returns the first audience value, or "" when none is present.
func (a audience) first() string {
	if len(a) == 0 {
		return ""
	}
	return a[0]
}

// minRSABits is the smallest RSA modulus accepted for RS256 verification.
const minRSABits = 2048

// keyResolver maps a token's kid (and the header alg, so a JWK that pins
// "alg" can be enforced) to a verification key.
type keyResolver func(kid, alg string) (crypto.PublicKey, error)

// verifySignature checks sig over signingInput. The header alg selects the
// algorithm and the resolved key MUST be of the matching type: an allowlist
// of EdDSA, ES256 and RS256 only (never none or HS*), so a token cannot pick
// a weaker verification path than the key was published for.
func verifySignature(alg string, key crypto.PublicKey, signingInput string, sig []byte) error {
	switch alg {
	case "EdDSA":
		pub, ok := key.(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			return errors.New("mcpresource: key is not an Ed25519 key")
		}
		if !ed25519.Verify(pub, []byte(signingInput), sig) {
			return errors.New("mcpresource: signature mismatch")
		}
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || pub.Curve.Params().Name != "P-256" {
			return errors.New("mcpresource: key is not a P-256 key")
		}
		if len(sig) != 64 {
			return errors.New("mcpresource: ES256 signature has wrong length")
		}
		h := sha256.Sum256([]byte(signingInput))
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, h[:], r, s) {
			return errors.New("mcpresource: signature mismatch")
		}
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("mcpresource: key is not an RSA key")
		}
		if pub.N.BitLen() < minRSABits {
			return errors.New("mcpresource: RSA key is too small")
		}
		h := sha256.Sum256([]byte(signingInput))
		// RS256 is RSASSA-PKCS1-v1_5 signature verification (RFC 7518 section
		// 3.3), not encryption. The padding is mandated by the algorithm.
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil { // NOSONAR go:S5542 false positive, signature verification
			return errors.New("mcpresource: signature mismatch")
		}
	default:
		return fmt.Errorf("mcpresource: unsupported alg %q", alg)
	}
	return nil
}

// verifyJWT performs the signature check (EdDSA, ES256 or RS256) plus structural validation:
// segment count, alg, kid, expiry, nbf, iat, audience. Returns the parsed
// claims on success.
func verifyJWT(token, expectedAud string, resolve keyResolver, now time.Time, skew time.Duration, allowMissingTyp bool) (*claims, error) {
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
	switch h.Alg {
	case "EdDSA", "ES256", "RS256":
	default:
		return nil, fmt.Errorf("mcpresource: unsupported alg %q", h.Alg)
	}
	// RFC 9068 section 4: access token JWTs carry typ "at+jwt". Requiring it
	// stops other JWTs signed by the same keys (ID tokens, assertions) from
	// being replayed as access tokens. WithAllowMissingTyp relaxes only the
	// absent case for authorization servers that do not set typ.
	if h.Typ == "" && !allowMissingTyp {
		return nil, errors.New("mcpresource: token header missing typ at+jwt")
	}
	if h.Typ != "" && h.Typ != "at+jwt" {
		return nil, fmt.Errorf("mcpresource: unsupported typ %q", h.Typ)
	}
	if h.Kid == "" {
		return nil, errors.New("mcpresource: token header missing kid")
	}
	key, err := resolve(h.Kid, h.Alg)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("mcpresource: signature decode: %w", err)
	}
	if err := verifySignature(h.Alg, key, parts[0]+"."+parts[1], sig); err != nil {
		return nil, err
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
	if expectedAud != "" && !c.Aud.contains(expectedAud) {
		return nil, fmt.Errorf("mcpresource: aud mismatch (got %q, want %q)", []string(c.Aud), expectedAud)
	}
	return &c, nil
}
