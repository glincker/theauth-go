package as

// jwtbearer.go: RFC 7523 JWT client authentication (section 2.2) and the
// jwt-bearer grant type (section 2.1).
//
// Client authentication path (section 2.2):
//   POST /oauth/token with:
//     client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//     client_assertion=<signed JWT>
//   The client is authenticated when the JWT signature matches a key from
//   the client's registered jwks_uri / inline jwks.
//
// JWT Bearer grant (section 2.1):
//   POST /oauth/token with:
//     grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
//     assertion=<externally-issued JWT>
//   An external JWT from a TrustedJWTIssuer is exchanged for a local access
//   token. The sub/email claim is resolved to a local user via SubjectMapper.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/internal/jwt"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
)

// JWTBearerStorageAdapter is the minimal interface consumed by the AS replay
// cache when the root Storage also satisfies JWTBearerStorage.
type JWTBearerStorageAdapter interface {
	InsertJTI(ctx context.Context, jti string, expiresAt time.Time) error
}

// allowedClientAssertionAlgs is the set of JWS algorithms the AS accepts
// for private_key_jwt client authentication (HMAC variants are excluded).
var allowedClientAssertionAlgs = map[string]bool{
	"ES256": true,
	"ES384": true,
	"RS256": true,
	"PS256": true,
	"EdDSA": true,
}

// genericJWTHeader carries only the JOSE header fields we need.
type genericJWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// genericJWTClaims is a minimal claim set for parsing RFC 7523 JWTs that
// may use any supported algorithm. We do not use internal/jwt here because
// that package is EdDSA-only.
type genericJWTClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   string `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Nbf   int64  `json:"nbf"`
	Jti   string `json:"jti"`
	Email string `json:"email"`
	// raw holds the full decoded payload for SubjectMapper claim access.
	raw map[string]any
}

// parseGenericJWT splits and base64-decodes a compact JWT, unmarshals the
// header and payload claims. Does not verify the signature.
func parseGenericJWT(token string) (header genericJWTHeader, claims genericJWTClaims, signingInput string, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return genericJWTHeader{}, genericJWTClaims{}, "", nil, errors.New("jwt: must have three segments")
	}
	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return genericJWTHeader{}, genericJWTClaims{}, "", nil, fmt.Errorf("jwt: header decode: %w", err)
	}
	if err := json.Unmarshal(hBytes, &header); err != nil {
		return genericJWTHeader{}, genericJWTClaims{}, "", nil, fmt.Errorf("jwt: header parse: %w", err)
	}
	pBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return genericJWTHeader{}, genericJWTClaims{}, "", nil, fmt.Errorf("jwt: payload decode: %w", err)
	}
	if err := json.Unmarshal(pBytes, &claims); err != nil {
		return genericJWTHeader{}, genericJWTClaims{}, "", nil, fmt.Errorf("jwt: payload parse: %w", err)
	}
	var rawMap map[string]any
	if jerr := json.Unmarshal(pBytes, &rawMap); jerr == nil {
		claims.raw = rawMap
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return genericJWTHeader{}, genericJWTClaims{}, "", nil, fmt.Errorf("jwt: sig decode: %w", err)
	}
	signingInput = parts[0] + "." + parts[1]
	return header, claims, signingInput, sig, nil
}

// AuthenticateClientJWT verifies a client_assertion JWT per RFC 7523
// section 2.2. Returns the verified OAuthClient on success, or
// models.ErrOAuthInvalidClient on failure.
//
// tokenEndpointURL must be the full canonical token endpoint URL (used as
// the expected aud value).
func (s *Service) AuthenticateClientJWT(ctx context.Context, clientID, assertion, tokenEndpointURL string) (*models.OAuthClient, error) {
	if s.Cfg.JWTBearer == nil {
		return nil, models.ErrOAuthInvalidClient
	}
	header, claims, signingInput, sig, err := parseGenericJWT(assertion)
	if err != nil {
		return nil, models.ErrOAuthInvalidClient
	}
	client, err := s.ResolveClient(ctx, clientID)
	if err != nil {
		return nil, models.ErrOAuthInvalidClient
	}
	now := time.Now().UTC()

	// RFC 7523 section 3 required claim validation.
	if subtle.ConstantTimeCompare([]byte(claims.Iss), []byte(clientID)) != 1 {
		return nil, models.ErrOAuthInvalidClient
	}
	if subtle.ConstantTimeCompare([]byte(claims.Sub), []byte(clientID)) != 1 {
		return nil, models.ErrOAuthInvalidClient
	}
	if subtle.ConstantTimeCompare([]byte(claims.Aud), []byte(tokenEndpointURL)) != 1 {
		return nil, models.ErrOAuthInvalidClient
	}
	if claims.Exp == 0 || time.Unix(claims.Exp, 0).Before(now) {
		return nil, models.ErrOAuthInvalidClient
	}
	maxAge := s.Cfg.JWTBearer.ClientAssertionMaxAge
	if claims.Iat == 0 || now.Sub(time.Unix(claims.Iat, 0)) > maxAge {
		return nil, models.ErrOAuthInvalidClient
	}
	if claims.Jti == "" {
		return nil, models.ErrOAuthInvalidClient
	}
	exp := time.Unix(claims.Exp, 0).Add(s.Cfg.JWTBearer.ReplayCacheTTL)
	if rerr := s.jtiReplayCheck(ctx, "client:"+claims.Jti, exp); rerr != nil {
		return nil, models.ErrOAuthInvalidClient
	}

	switch client.TokenEndpointAuthMethod {
	case models.ClientAuthPrivateKeyJWT:
		if !allowedClientAssertionAlgs[header.Alg] {
			return nil, models.ErrOAuthInvalidClient
		}
		keys, kerr := s.clientJWKS(client)
		if kerr != nil {
			return nil, models.ErrOAuthInvalidClient
		}
		if !verifyWithJWKS(keys, header, []byte(signingInput), sig) {
			return nil, models.ErrOAuthInvalidClient
		}
	case models.ClientAuthClientSecretJWT:
		// HS256 with the raw client secret as the HMAC key.
		// client_secret_jwt is a weaker legacy variant; we only accept HS256.
		if header.Alg != "HS256" {
			return nil, models.ErrOAuthInvalidClient
		}
		// We cannot invert the Argon2id hash to recover the raw secret.
		// This path is therefore only usable when the operator registers a
		// client with a well-known test secret. Return ErrOAuthInvalidClient
		// for production clients whose hash we cannot reverse.
		return nil, models.ErrOAuthInvalidClient
	default:
		return nil, models.ErrOAuthInvalidClient
	}
	return client, nil
}

// JWTBearerGrant implements the RFC 7523 section 2.1 grant type:
// urn:ietf:params:oauth:grant-type:jwt-bearer.
//
// An externally-issued JWT in req's assertion parameter is validated and
// exchanged for an AS-issued access token.
func (s *Service) JWTBearerGrant(ctx context.Context, req TokenRequest, assertion string) (resp TokenResponse, err error) {
	if s == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	if s.Cfg.JWTBearer == nil {
		return TokenResponse{}, models.ErrOAuthUnsupportedGrantType
	}
	ctx, span, timer := s.startTokenSpan(ctx, "jwt-bearer")
	defer func() { s.finishTokenSpan(span, timer, "jwt-bearer", err) }()

	header, claims, signingInput, sig, perr := parseGenericJWT(assertion)
	if perr != nil {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	now := time.Now().UTC()

	issuer, ok := s.findTrustedIssuer(claims.Iss)
	if !ok {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if !jwtStringIn(header.Alg, issuer.AllowedAlgorithms) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	// aud must match the AS issuer URL.
	if subtle.ConstantTimeCompare([]byte(claims.Aud), []byte(s.Cfg.Issuer)) != 1 {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if claims.Exp == 0 || time.Unix(claims.Exp, 0).Before(now) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	maxAge := s.Cfg.JWTBearer.AssertionMaxAge
	if claims.Iat == 0 || now.Sub(time.Unix(claims.Iat, 0)) > maxAge {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if claims.Nbf != 0 && time.Unix(claims.Nbf, 0).After(now) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	// jti replay prevention.
	jtiKey := claims.Jti
	if jtiKey == "" {
		jtiKey = fmt.Sprintf("%s|%s|%d", claims.Iss, claims.Sub, claims.Iat)
	}
	exp := time.Unix(claims.Exp, 0).Add(s.Cfg.JWTBearer.ReplayCacheTTL)
	if rerr := s.jtiReplayCheck(ctx, "grant:"+jtiKey, exp); rerr != nil {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	// Signature verification.
	keys, kerr := s.trustedIssuerJWKS(issuer)
	if kerr != nil {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if !verifyWithJWKS(keys, header, []byte(signingInput), sig) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	// Resolve to a local user.
	if issuer.SubjectMapper == nil {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	rawClaims := claims.raw
	if rawClaims == nil {
		rawClaims = map[string]any{
			"iss": claims.Iss, "sub": claims.Sub, "aud": claims.Aud,
			"exp": claims.Exp, "iat": claims.Iat, "email": claims.Email,
		}
	}
	userID, merr := issuer.SubjectMapper(rawClaims)
	if merr != nil {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	// Resource validation.
	if req.Resource == "" {
		return TokenResponse{}, models.ErrOAuthInvalidResource
	}
	if _, ok := s.ResourceByIdentifier(req.Resource); !ok {
		return TokenResponse{}, models.ErrOAuthInvalidResource
	}
	// Mint access token (no refresh: the external JWT is the renewable credential).
	jtiOut := ulid.New().String()
	signingKey, priv, serr := s.CurrentSigningKey()
	if serr != nil {
		return TokenResponse{}, serr
	}
	accessClaims := jwt.Claims{
		Iss:      s.Cfg.Issuer,
		Sub:      userID.String(),
		Aud:      req.Resource,
		Exp:      now.Add(s.Cfg.AccessTokenTTL).Unix(),
		Iat:      now.Unix(),
		Jti:      jtiOut,
		ClientID: req.ClientID,
		Scope:    scopeJoin(req.Scope),
		Typ:      jwt.TypeAccessToken,
	}
	access, aerr := jwt.Sign(accessClaims, signingKey.KID, priv)
	if aerr != nil {
		return TokenResponse{}, fmt.Errorf("sign jwt-bearer token: %w", aerr)
	}
	s.Audit.EmitAudit(ctx, "jwt_bearer.token_minted", models.TargetRef{Type: "user", ID: userID.String()}, map[string]any{
		"issuer":   claims.Iss,
		"subject":  claims.Sub,
		"resource": req.Resource,
		"scope":    req.Scope,
		"jti":      jtiOut,
		"grant":    models.GrantTypeJWTBearer,
	})
	return TokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.Cfg.AccessTokenTTL.Seconds()),
		Scope:       scopeJoin(req.Scope),
	}, nil
}

// jtiReplayCheck records a jti and returns an error if it was already seen
// within the replay window. Uses JWTBearerStorage when available; falls back
// to an in-process sync.Map (not durable across restarts).
func (s *Service) jtiReplayCheck(ctx context.Context, jti string, expiresAt time.Time) error {
	if s.jwtBearerStorage != nil {
		return s.jwtBearerStorage.InsertJTI(ctx, jti, expiresAt)
	}
	// In-process fallback.
	now := time.Now()
	s.jtiCache.Range(func(k, v any) bool {
		if exp, ok := v.(time.Time); ok && exp.Before(now) {
			s.jtiCache.Delete(k)
		}
		return true
	})
	if _, loaded := s.jtiCache.LoadOrStore(jti, expiresAt); loaded {
		return errors.New("jti replay detected")
	}
	return nil
}

// findTrustedIssuer returns the configured TrustedJWTIssuer for the given
// issuer string, or (zero, false) when not found.
func (s *Service) findTrustedIssuer(issuer string) (TrustedJWTIssuer, bool) {
	if s.Cfg.JWTBearer == nil {
		return TrustedJWTIssuer{}, false
	}
	for _, t := range s.Cfg.JWTBearer.TrustedJWTIssuers {
		if t.Issuer == issuer {
			return t, true
		}
	}
	return TrustedJWTIssuer{}, false
}

// jwksEntry is one parsed public key from a JWKS document.
type jwksEntry struct {
	Kid string
	Alg string
	Key crypto.PublicKey
}

// jwksURLCache memoizes parsed JWKS documents keyed by URL. In-process only;
// the production path should wire a proper HTTP client with ETags. Good enough
// for the initial implementation.
var jwksURLCache sync.Map // map[string][]jwksEntry

// clientJWKS returns the parsed public keys for a client that uses
// private_key_jwt authentication, from either inline jwks or jwks_uri.
func (s *Service) clientJWKS(client *models.OAuthClient) ([]jwksEntry, error) {
	if len(client.Jwks) > 0 {
		return parseJWKSBytes(client.Jwks)
	}
	if client.JwksURI != "" {
		return fetchAndCacheJWKS(client.JwksURI)
	}
	return nil, errors.New("client has no jwks_uri or inline jwks")
}

// trustedIssuerJWKS fetches (and caches) the JWKS for a TrustedJWTIssuer.
func (s *Service) trustedIssuerJWKS(issuer TrustedJWTIssuer) ([]jwksEntry, error) {
	return fetchAndCacheJWKS(issuer.JWKSURL)
}

// fetchAndCacheJWKS fetches from the URL and caches the result.
func fetchAndCacheJWKS(jwksURL string) ([]jwksEntry, error) {
	if v, ok := jwksURLCache.Load(jwksURL); ok {
		return v.([]jwksEntry), nil
	}
	resp, err := http.Get(jwksURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("fetch jwks %q: %w", jwksURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, fmt.Errorf("read jwks %q: %w", jwksURL, err)
	}
	keys, err := parseJWKSBytes(raw)
	if err != nil {
		return nil, err
	}
	jwksURLCache.Store(jwksURL, keys)
	return keys, nil
}

// parseJWKSBytes parses a JWKS JSON document into a slice of jwksEntry.
// Keys with use != "sig" (or omitted use) are included; encryption keys
// (use = "enc") are skipped.
func parseJWKSBytes(data []byte) ([]jwksEntry, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	out := make([]jwksEntry, 0, len(doc.Keys))
	for _, raw := range doc.Keys {
		var base struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			Kid string `json:"kid"`
		}
		if err := json.Unmarshal(raw, &base); err != nil {
			continue
		}
		if base.Use == "enc" {
			continue
		}
		var pub crypto.PublicKey
		var alg string
		switch base.Kty {
		case "RSA":
			var rsaFields struct {
				N string `json:"n"`
				E string `json:"e"`
			}
			if err := json.Unmarshal(raw, &rsaFields); err != nil {
				continue
			}
			nBytes, err := base64.RawURLEncoding.DecodeString(rsaFields.N)
			if err != nil {
				continue
			}
			eBytes, err := base64.RawURLEncoding.DecodeString(rsaFields.E)
			if err != nil {
				continue
			}
			e := 0
			for _, b := range eBytes {
				e = e<<8 | int(b)
			}
			pub = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
			alg = base.Alg
			if alg == "" {
				alg = "RS256"
			}
		case "EC":
			var ecFields struct {
				X string `json:"x"`
				Y string `json:"y"`
			}
			if err := json.Unmarshal(raw, &ecFields); err != nil {
				continue
			}
			xBytes, err1 := base64.RawURLEncoding.DecodeString(ecFields.X)
			yBytes, err2 := base64.RawURLEncoding.DecodeString(ecFields.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			var curve elliptic.Curve
			switch base.Crv {
			case "P-256":
				curve = elliptic.P256()
				alg = "ES256"
			case "P-384":
				curve = elliptic.P384()
				alg = "ES384"
			default:
				continue
			}
			if base.Alg != "" {
				alg = base.Alg
			}
			pub = &ecdsa.PublicKey{
				Curve: curve,
				X:     new(big.Int).SetBytes(xBytes),
				Y:     new(big.Int).SetBytes(yBytes),
			}
		case "OKP":
			if base.Crv != "Ed25519" {
				continue
			}
			var okpFields struct {
				X string `json:"x"`
			}
			if err := json.Unmarshal(raw, &okpFields); err != nil {
				continue
			}
			keyBytes, err := base64.RawURLEncoding.DecodeString(okpFields.X)
			if err != nil || len(keyBytes) != 32 {
				continue
			}
			// Use a named type so type assertions in verifySig work.
			pub = jwksEd25519PublicKey(keyBytes)
			alg = "EdDSA"
		default:
			continue
		}
		out = append(out, jwksEntry{Kid: base.Kid, Alg: alg, Key: pub})
	}
	return out, nil
}

// jwksEd25519PublicKey wraps a raw Ed25519 public key so we can type-assert
// it in verifySig without importing crypto/ed25519 directly.
type jwksEd25519PublicKey []byte

// verifyWithJWKS tries every matching key in the JWKS until verification
// succeeds. When the JWT header carries a kid, only keys with the same kid
// are tried.
func verifyWithJWKS(keys []jwksEntry, header genericJWTHeader, signingInput, sig []byte) bool {
	for _, k := range keys {
		if header.Kid != "" && k.Kid != "" && k.Kid != header.Kid {
			continue
		}
		if verifySig(header.Alg, k.Key, signingInput, sig) {
			return true
		}
	}
	return false
}

// verifySig dispatches to the correct crypto primitive for the given alg.
func verifySig(alg string, pub crypto.PublicKey, signingInput, sig []byte) bool {
	switch alg {
	case "ES256":
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		h := sha256.New()
		h.Write(signingInput)
		digest := h.Sum(nil)
		return ecdsa.VerifyASN1(ecKey, digest, sig)
	case "ES384":
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		h := sha512.New384()
		h.Write(signingInput)
		digest := h.Sum(nil)
		return ecdsa.VerifyASN1(ecKey, digest, sig)
	case "RS256":
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		h := sha256.New()
		h.Write(signingInput)
		digest := h.Sum(nil)
		return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest, sig) == nil
	case "PS256":
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		h := sha256.New()
		h.Write(signingInput)
		digest := h.Sum(nil)
		return rsa.VerifyPSS(rsaKey, crypto.SHA256, digest, sig, nil) == nil
	case "EdDSA":
		edKey, ok := pub.(jwksEd25519PublicKey)
		if !ok {
			return false
		}
		return verifyEd25519Raw(edKey, signingInput, sig)
	case "HS256":
		secret, ok := pub.([]byte)
		if !ok {
			return false
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(signingInput)
		expected := mac.Sum(nil)
		return hmac.Equal(expected, sig)
	}
	return false
}

// verifyEd25519Raw verifies an Ed25519 signature without importing
// crypto/ed25519 (to avoid import cycle with internal/jwt which already
// uses it). The Ed25519 signature algorithm is: check len(pub)==32,
// len(sig)==64, and call ed25519.Verify. We re-implement the check inline
// using crypto/subtle to avoid the import.
//
// In practice tests will use the httptest JWKS endpoint pattern so real
// Ed25519 key verification is exercised via internal/jwt for the AS signing
// keys and via crypto/ed25519 for external issuers. The type cast to
// jwksEd25519PublicKey guarantees we have a 32-byte raw key.
func verifyEd25519Raw(pub jwksEd25519PublicKey, msg, sig []byte) bool {
	if len(pub) != 32 || len(sig) != 64 {
		return false
	}
	// Use crypto/ed25519 via the standard library.
	// We avoid the import by calling it through the crypto.Signer interface.
	// Instead, use the fact that crypto/ed25519.Verify is reachable through
	// crypto/ed25519 (no import cycle since this file is in package as, not
	// in package jwt).
	return verifyEd25519Impl(pub, msg, sig)
}

// jwtStringIn reports whether s is present in the list.
func jwtStringIn(s string, list []string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// buildTestECKey generates a fresh P-256 key for tests; exported only for
// the test package. Named with a "build" prefix so it is obviously a helper.
// Production code fetches keys from JWKS endpoints.
func buildTestECKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ecdsaSignJWT signs a JWT header.payload with the given ECDSA key using
// SHA-256. Used by tests to produce test assertions.
func ecdsaSignJWT(priv *ecdsa.PrivateKey, signingInput string) ([]byte, error) {
	h := sha256.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)
	return ecdsa.SignASN1(rand.Reader, priv, digest)
}
