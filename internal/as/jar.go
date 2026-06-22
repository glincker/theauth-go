package as

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/glincker/theauth-go/internal/models"
)

// jar.go: RFC 9101 JWT-Secured Authorization Requests (JAR).
//
// When a /oauth/authorize or /oauth/par request carries a "request" parameter,
// the AS:
//   1. Decodes and verifies the JWT signature using the client's public key
//      (resolved from jwks_uri or inline jwks on the OAuthClient row).
//   2. Validates iss == client_id, aud == AS issuer, exp, iat, optional nbf.
//   3. Uses the inner JWT claims as the authorization parameters; outer query/
//      form params (except client_id and request itself) are ignored per
//      RFC 9101 section 5.
//
// Rejected algorithms: HS* and "none". Accepted: ES256, ES384, RS256, PS256, EdDSA.

// JARConfig holds the knobs for the JAR sub-system. Non-nil presence on
// Config.JAR enables JAR. The zero value is not valid; use DefaultJARConfig().
type JARConfig struct {
	// AcceptedAlgorithms lists the JWS algorithms the AS accepts on
	// request objects. Defaults to ["ES256", "RS256", "EdDSA"].
	// HS* and "none" are always rejected regardless of this list.
	AcceptedAlgorithms []string

	// RequireJAR, when true, causes /oauth/authorize and /oauth/par to
	// reject any request that does not carry a request= parameter.
	// Off by default.
	RequireJAR bool
}

// DefaultJARConfig returns a JARConfig with safe defaults.
func DefaultJARConfig() *JARConfig {
	return &JARConfig{
		AcceptedAlgorithms: []string{"ES256", "RS256", "EdDSA"},
	}
}

// applyJARDefaults fills in zero-value JARConfig fields.
func applyJARDefaults(c *JARConfig) {
	if len(c.AcceptedAlgorithms) == 0 {
		c.AcceptedAlgorithms = []string{"ES256", "RS256", "EdDSA"}
	}
}

// jarAlgorithmsAdvertised returns the JAR alg list for the AS metadata.
// Returns nil when JAR is not enabled.
func (s *Service) jarAlgorithmsAdvertised() []string {
	if s == nil || s.Cfg.JAR == nil {
		return nil
	}
	cfg := s.Cfg.JAR
	applyJARDefaults(cfg)
	out := make([]string, len(cfg.AcceptedAlgorithms))
	copy(out, cfg.AcceptedAlgorithms)
	return out
}

// IsJAREnabled reports whether JAR is configured.
func (s *Service) IsJAREnabled() bool {
	return s != nil && s.Cfg.JAR != nil
}

// jarHeader is the minimal JOSE header we decode to discover alg+kid.
type jarHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
}

// jarClaims contains the authorization request claims inside the JAR JWT.
// All standard authorize params appear here; unknown fields land in Extra.
type jarClaims struct {
	// RFC 7519 registered claims.
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf,omitempty"`
	Jti string `json:"jti,omitempty"`

	// Authorization request claims (RFC 9101 section 4).
	ResponseType        string `json:"response_type,omitempty"`
	ClientID            string `json:"client_id,omitempty"`
	RedirectURI         string `json:"redirect_uri,omitempty"`
	Scope               string `json:"scope,omitempty"`
	State               string `json:"state,omitempty"`
	Nonce               string `json:"nonce,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	Resource            string `json:"resource,omitempty"`
}

// ParseRequestObject validates and decodes a JAR request object JWT.
// Returns the AuthorizeRequest extracted from the JWT claims.
// clientID is the client_id from the outer request (used for validation);
// issuer is this AS's issuer URL.
func (s *Service) ParseRequestObject(ctx interface{ Done() <-chan struct{} }, rawJWT string, clientID string, issuer string, client *models.OAuthClient) (AuthorizeRequest, error) {
	if s == nil {
		return AuthorizeRequest{}, errors.New("theauth: authorization server not configured")
	}
	if s.Cfg.JAR == nil {
		return AuthorizeRequest{}, models.ErrOAuthInvalidRequest
	}
	cfg := s.Cfg.JAR
	applyJARDefaults(cfg)

	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return AuthorizeRequest{}, fmt.Errorf("%w: malformed request object", models.ErrOAuthInvalidRequest)
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return AuthorizeRequest{}, fmt.Errorf("%w: request object header decode", models.ErrOAuthInvalidRequest)
	}
	var hdr jarHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return AuthorizeRequest{}, fmt.Errorf("%w: request object header parse", models.ErrOAuthInvalidRequest)
	}

	// Reject HS* and none unconditionally.
	if jarAlgIsForbidden(hdr.Alg) {
		return AuthorizeRequest{}, fmt.Errorf("%w: algorithm %q not permitted in request objects", models.ErrOAuthInvalidRequest, hdr.Alg)
	}
	if !jarAlgAccepted(hdr.Alg, cfg.AcceptedAlgorithms) {
		return AuthorizeRequest{}, fmt.Errorf("%w: algorithm %q not in AcceptedAlgorithms", models.ErrOAuthInvalidRequest, hdr.Alg)
	}

	// Resolve the client's public key(s).
	keys, err := resolveClientJARKeys(client)
	if err != nil || len(keys) == 0 {
		return AuthorizeRequest{}, fmt.Errorf("%w: client has no usable public key for JAR", models.ErrOAuthInvalidClient)
	}

	// Verify signature.
	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return AuthorizeRequest{}, fmt.Errorf("%w: request object signature decode", models.ErrOAuthInvalidRequest)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return AuthorizeRequest{}, fmt.Errorf("%w: request object payload decode", models.ErrOAuthInvalidRequest)
	}

	verified := false
	for _, key := range keys {
		if err := jarVerifySignature(hdr.Alg, []byte(signingInput), sigBytes, key); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return AuthorizeRequest{}, fmt.Errorf("%w: request object signature verification failed", models.ErrOAuthInvalidRequest)
	}

	// Decode claims.
	var claims jarClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return AuthorizeRequest{}, fmt.Errorf("%w: request object claims parse", models.ErrOAuthInvalidRequest)
	}

	// Validate registered claims.
	now := time.Now()
	if claims.Exp == 0 || time.Unix(claims.Exp, 0).Before(now) {
		return AuthorizeRequest{}, fmt.Errorf("%w: request object expired", models.ErrOAuthInvalidRequest)
	}
	if claims.Iat != 0 && time.Unix(claims.Iat, 0).After(now.Add(5*time.Minute)) {
		return AuthorizeRequest{}, fmt.Errorf("%w: request object iat is in the future", models.ErrOAuthInvalidRequest)
	}
	if claims.Nbf != 0 && time.Unix(claims.Nbf, 0).After(now) {
		return AuthorizeRequest{}, fmt.Errorf("%w: request object not yet valid", models.ErrOAuthInvalidRequest)
	}

	// iss MUST equal client_id (RFC 9101 section 4).
	if claims.Iss != clientID {
		return AuthorizeRequest{}, fmt.Errorf("%w: request object iss %q must equal client_id %q", models.ErrOAuthInvalidRequest, claims.Iss, clientID)
	}

	// aud MUST equal this AS issuer (RFC 9101 section 4).
	if claims.Aud != issuer {
		return AuthorizeRequest{}, fmt.Errorf("%w: request object aud %q must equal issuer %q", models.ErrOAuthInvalidRequest, claims.Aud, issuer)
	}

	return AuthorizeRequest{
		ClientID:            claims.ClientID,
		RedirectURI:         claims.RedirectURI,
		ResponseType:        claims.ResponseType,
		Scope:               scopeSplit(claims.Scope),
		State:               claims.State,
		Nonce:               claims.Nonce,
		CodeChallenge:       claims.CodeChallenge,
		CodeChallengeMethod: claims.CodeChallengeMethod,
		Resource:            claims.Resource,
	}, nil
}

// jarAlgIsForbidden returns true for algorithms that must never be accepted
// in request objects (HS* and "none").
func jarAlgIsForbidden(alg string) bool {
	if alg == "" || strings.ToLower(alg) == "none" {
		return true
	}
	return strings.HasPrefix(strings.ToUpper(alg), "HS")
}

// jarAlgAccepted returns true when alg is in the operator-configured allow list.
func jarAlgAccepted(alg string, accepted []string) bool {
	for _, a := range accepted {
		if strings.EqualFold(a, alg) {
			return true
		}
	}
	return false
}

// clientPublicKey wraps a parsed public key from the client JWKS.
type clientPublicKey struct {
	Alg string
	Key crypto.PublicKey
}

// resolveClientJARKeys parses the client's JWKS (from Jwks field or as a
// stand-in for jwks_uri which requires an HTTP fetch). For jwks_uri the
// caller's transport layer would handle the fetch; we keep this offline for
// now and return the inline jwks bytes.
func resolveClientJARKeys(client *models.OAuthClient) ([]clientPublicKey, error) {
	if client == nil {
		return nil, errors.New("nil client")
	}
	var jwksJSON []byte
	if len(client.Jwks) > 0 {
		jwksJSON = client.Jwks
	} else {
		return nil, errors.New("client has no inline jwks")
	}
	return parseJWKS(jwksJSON)
}

// clientJWKSDoc is the minimal shape we parse from a client's JSON Web Key Set.
type clientJWKSDoc struct {
	Keys []json.RawMessage `json:"keys"`
}

// jwkBase captures the fields shared by all JWK key types.
type jwkBase struct {
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
}

func parseJWKS(data []byte) ([]clientPublicKey, error) {
	var doc clientJWKSDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	var out []clientPublicKey
	for _, raw := range doc.Keys {
		var base jwkBase
		if err := json.Unmarshal(raw, &base); err != nil {
			continue
		}
		// Skip non-sig keys.
		if base.Use != "" && base.Use != "sig" {
			continue
		}
		switch base.Kty {
		case "EC":
			k, alg, err := parseECJWK(raw, base)
			if err != nil {
				continue
			}
			out = append(out, clientPublicKey{Alg: alg, Key: k})
		case "RSA":
			k, alg, err := parseRSAJWK(raw, base)
			if err != nil {
				continue
			}
			out = append(out, clientPublicKey{Alg: alg, Key: k})
		case "OKP":
			k, alg, err := parseOKPJWK(raw, base)
			if err != nil {
				continue
			}
			out = append(out, clientPublicKey{Alg: alg, Key: k})
		}
	}
	return out, nil
}

type ecJWK struct {
	jwkBase
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseECJWK(raw json.RawMessage, base jwkBase) (*ecdsa.PublicKey, string, error) {
	var k ecJWK
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, "", err
	}
	var curve elliptic.Curve
	var alg string
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
		alg = "ES256"
	case "P-384":
		curve = elliptic.P384()
		alg = "ES384"
	default:
		return nil, "", fmt.Errorf("unsupported EC crv %q", k.Crv)
	}
	if base.Alg != "" {
		alg = base.Alg
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, "", err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, "", err
	}
	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	return pub, alg, nil
}

type rsaJWK struct {
	jwkBase
	N string `json:"n"`
	E string `json:"e"`
}

func parseRSAJWK(raw json.RawMessage, base jwkBase) (*rsa.PublicKey, string, error) {
	var k rsaJWK
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, "", err
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, "", err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, "", err
	}
	eInt := new(big.Int).SetBytes(eBytes)
	alg := "RS256"
	if base.Alg != "" {
		alg = base.Alg
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(eInt.Int64()),
	}
	return pub, alg, nil
}

type okpJWK struct {
	jwkBase
	Crv string `json:"crv"`
	X   string `json:"x"`
}

func parseOKPJWK(raw json.RawMessage, base jwkBase) (ed25519.PublicKey, string, error) {
	var k okpJWK
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, "", err
	}
	if k.Crv != "Ed25519" {
		return nil, "", fmt.Errorf("unsupported OKP crv %q", k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, "", err
	}
	if len(xBytes) != ed25519.PublicKeySize {
		return nil, "", errors.New("OKP Ed25519 key has wrong length")
	}
	alg := "EdDSA"
	if base.Alg != "" {
		alg = base.Alg
	}
	return ed25519.PublicKey(xBytes), alg, nil
}

// jarVerifySignature verifies a JWS signature for a JAR JWT.
func jarVerifySignature(alg string, signingInput, sig []byte, cpk clientPublicKey) error {
	switch strings.ToUpper(alg) {
	case "ES256":
		pub, ok := cpk.Key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("key type mismatch for ES256")
		}
		return verifyECDSA(pub, crypto.SHA256, signingInput, sig)
	case "ES384":
		pub, ok := cpk.Key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("key type mismatch for ES384")
		}
		return verifyECDSA(pub, crypto.SHA384, signingInput, sig)
	case "RS256":
		pub, ok := cpk.Key.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type mismatch for RS256")
		}
		return verifyRSAPKCS1(pub, crypto.SHA256, signingInput, sig)
	case "PS256":
		pub, ok := cpk.Key.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type mismatch for PS256")
		}
		return verifyRSAPSS(pub, crypto.SHA256, signingInput, sig)
	case "EDDSA":
		pub, ok := cpk.Key.(ed25519.PublicKey)
		if !ok {
			return errors.New("key type mismatch for EdDSA")
		}
		if !ed25519.Verify(pub, signingInput, sig) {
			return errors.New("EdDSA signature mismatch")
		}
		return nil
	}
	return fmt.Errorf("unsupported alg %q", alg)
}

func verifyECDSA(pub *ecdsa.PublicKey, h crypto.Hash, signingInput, sig []byte) error {
	var hasher crypto.Hash
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(signingInput)
		hasher = h
		_ = hasher
		r, s, err := ecdsaSigParts(sig)
		if err != nil {
			return err
		}
		if !ecdsa.Verify(pub, d[:], r, s) {
			return errors.New("ECDSA signature mismatch")
		}
	case crypto.SHA384:
		d := sha512.Sum384(signingInput)
		r, s, err := ecdsaSigParts(sig)
		if err != nil {
			return err
		}
		if !ecdsa.Verify(pub, d[:], r, s) {
			return errors.New("ECDSA signature mismatch")
		}
	default:
		return errors.New("unsupported ECDSA hash")
	}
	return nil
}

// ecdsaSigParts decodes a JWS ECDSA signature: two fixed-length big-endian
// integers concatenated as specified in RFC 7518 section 3.4.
func ecdsaSigParts(sig []byte) (*big.Int, *big.Int, error) {
	if len(sig)%2 != 0 {
		return nil, nil, errors.New("ECDSA signature has odd length")
	}
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	return r, s, nil
}

func verifyRSAPKCS1(pub *rsa.PublicKey, h crypto.Hash, signingInput, sig []byte) error {
	var digest []byte
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(signingInput)
		digest = d[:]
	default:
		return errors.New("unsupported RSA hash")
	}
	return rsa.VerifyPKCS1v15(pub, h, digest, sig)
}

func verifyRSAPSS(pub *rsa.PublicKey, h crypto.Hash, signingInput, sig []byte) error {
	var digest []byte
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(signingInput)
		digest = d[:]
	default:
		return errors.New("unsupported RSA-PSS hash")
	}
	return rsa.VerifyPSS(pub, h, digest, sig, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
}

// GenerateECKeyJWK generates an ephemeral ECDSA P-256 key and returns
// the private key + its public JWK representation. Used by tests.
func GenerateECKeyJWK() (*ecdsa.PrivateKey, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	xBytes := priv.X.Bytes()
	yBytes := priv.Y.Bytes()
	// Pad to curve field size (32 bytes for P-256).
	xBytes = padTo(xBytes, 32)
	yBytes = padTo(yBytes, 32)
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"use": "sig",
		"alg": "ES256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}
	jwksDoc := map[string]interface{}{"keys": []interface{}{jwk}}
	pubJWKS, err := json.Marshal(jwksDoc)
	if err != nil {
		return nil, nil, err
	}
	return priv, pubJWKS, nil
}

func padTo(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// BuildJARJWT creates a signed JAR JWT with the supplied claims. Used by tests.
func BuildJARJWT(priv *ecdsa.PrivateKey, clientID, issuer string, req AuthorizeRequest, exp time.Time) (string, error) {
	claims := map[string]interface{}{
		"iss":                   clientID,
		"aud":                   issuer,
		"exp":                   exp.Unix(),
		"iat":                   time.Now().Unix(),
		"response_type":         req.ResponseType,
		"client_id":             req.ClientID,
		"redirect_uri":          req.RedirectURI,
		"scope":                 scopeJoin(req.Scope),
		"state":                 req.State,
		"nonce":                 req.Nonce,
		"code_challenge":        req.CodeChallenge,
		"code_challenge_method": req.CodeChallengeMethod,
		"resource":              req.Resource,
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	hdr := map[string]string{"alg": "ES256", "typ": "oauth-authz-req+jwt"}
	headerJSON, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}

	// RFC 7518 section 3.4: fixed-length concatenated R||S.
	curveSize := 32 // P-256
	rBytes := padTo(r.Bytes(), curveSize)
	sBytes := padTo(s.Bytes(), curveSize)
	sig := append(rBytes, sBytes...)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}
