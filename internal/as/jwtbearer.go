package as

// jwtbearer.go implements RFC 7523 JWT client authentication (section 2.2) and the jwt-bearer grant
// (section 2.1). Client auth verifies a client_assertion against the client's registered keys. The
// grant exchanges an external JWT from a TrustedJWTIssuer for a local access token, resolving its
// subject through SubjectMapper.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// JWTBearerStorageAdapter is the minimal replay-cache interface, used when the root Storage
// implements JWTBearerStorage.
type JWTBearerStorageAdapter interface {
	InsertJTI(ctx context.Context, jti string, expiresAt time.Time) error
}

// allowedClientAssertionAlgs lists the JWS algorithms accepted for private_key_jwt. HMAC variants
// are excluded.
var allowedClientAssertionAlgs = map[string]bool{
	"ES256": true,
	"ES384": true,
	"RS256": true,
	"PS256": true,
	"EdDSA": true,
}

type genericJWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// genericJWTClaims is a minimal claim set for RFC 7523 JWTs using any supported algorithm.
// internal/jwt is EdDSA only, so it is not used.
type genericJWTClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   string `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Nbf   int64  `json:"nbf"`
	Jti   string `json:"jti"`
	Email string `json:"email"`
	raw   map[string]any
}

// parseGenericJWT splits and decodes a compact JWT. It does not verify the signature.
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

// AuthenticateClientJWT verifies a client_assertion per RFC 7523 section 2.2 and returns the
// client, or ErrOAuthInvalidClient. tokenEndpointURL is the expected aud.
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

	if subtle.ConstantTimeCompare([]byte(claims.Iss), []byte(clientID)) != 1 {
		return nil, models.ErrOAuthInvalidClient
	}
	if subtle.ConstantTimeCompare([]byte(claims.Sub), []byte(clientID)) != 1 {
		return nil, models.ErrOAuthInvalidClient
	}
	if subtle.ConstantTimeCompare([]byte(claims.Aud), []byte(tokenEndpointURL)) != 1 {
		return nil, models.ErrOAuthInvalidClient
	}
	if claims.Exp == 0 || time.Unix(claims.Exp, 0).Add(s.Cfg.ClockSkew).Before(now) {
		return nil, models.ErrOAuthInvalidClient
	}
	maxAge := s.Cfg.JWTBearer.ClientAssertionMaxAge
	if claims.Iat == 0 || now.Sub(time.Unix(claims.Iat, 0)) > maxAge+s.Cfg.ClockSkew {
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
		// client_secret_jwt (HS256 with the raw secret) is a weaker legacy variant, so only HS256 is accepted.
		if header.Alg != "HS256" {
			return nil, models.ErrOAuthInvalidClient
		}
		// The Argon2id hash cannot be reversed to the raw secret, so client_secret_jwt works only for
		// clients with a known secret. Production clients whose hash cannot be reversed get
		// ErrOAuthInvalidClient.
		return nil, models.ErrOAuthInvalidClient
	default:
		return nil, models.ErrOAuthInvalidClient
	}
	return client, nil
}

// JWTBearerGrant implements the RFC 7523 section 2.1 jwt-bearer grant. The assertion is validated
// and exchanged for an access token.
func (s *Service) JWTBearerGrant(ctx context.Context, req TokenRequest, assertion string) (resp TokenResponse, err error) {
	if s == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	if r, handled, derr := s.tryDeviceAssertion(ctx, req, assertion); handled {
		return r, derr
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
	wantAud := s.Cfg.Issuer
	if issuer.Audience != "" {
		wantAud = issuer.Audience
	}
	if subtle.ConstantTimeCompare([]byte(claims.Aud), []byte(wantAud)) != 1 {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if claims.Exp == 0 || time.Unix(claims.Exp, 0).Add(s.Cfg.ClockSkew).Before(now) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	maxAge := s.Cfg.JWTBearer.AssertionMaxAge
	if claims.Iat == 0 || now.Sub(time.Unix(claims.Iat, 0)) > maxAge+s.Cfg.ClockSkew {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if claims.Nbf != 0 && time.Unix(claims.Nbf, 0).Add(-s.Cfg.ClockSkew).After(now) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	jtiKey := claims.Jti
	if jtiKey == "" {
		jtiKey = fmt.Sprintf("%s|%s|%d", claims.Iss, claims.Sub, claims.Iat)
	}
	exp := time.Unix(claims.Exp, 0).Add(s.Cfg.JWTBearer.ReplayCacheTTL)
	if rerr := s.jtiReplayCheck(ctx, "grant:"+jtiKey, exp); rerr != nil {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	keys, kerr := s.trustedIssuerJWKS(issuer)
	if kerr != nil {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if !verifyWithJWKS(keys, header, []byte(signingInput), sig) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	// Required claims run only on a verified payload. A missing payload fails closed when any matcher
	// is configured.
	if len(issuer.RequiredClaims) > 0 {
		if failed := failedClaims(issuer.RequiredClaims, claims.raw); len(failed) > 0 {
			s.auditClaimsDenied(ctx, req, issuer.Issuer, failed)
			return TokenResponse{}, models.ErrOAuthInvalidGrant
		}
	}
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
	_, audience, rerr := s.resolveResource(req.Resource)
	if rerr != nil {
		return TokenResponse{}, rerr
	}
	if req.Resource == "" {
		// OptionalResource defaulted the audience; the ID-JAG check below compares against req.Resource.
		req.Resource = audience
	}
	grantScope := req.Scope
	if header.Typ == jwt.TypeIDJAG {
		if grantScope, err = s.vetIDJAGRedemption(ctx, req, claims.raw); err != nil {
			return TokenResponse{}, err
		}
	}
	// An agent client's policy and rate limit apply to this mint too.
	var gated models.AgentMintResult
	var agentExp time.Time
	if req.ClientID != "" {
		if ag, lerr := s.Storage.AgentByClientID(ctx, req.ClientID); lerr == nil && ag != nil {
			// An expired agent mints nothing, and its tokens never outlive it.
			if aerr := agentLiveErr(ag, s.now()); aerr != nil {
				return TokenResponse{}, aerr
			}
			agentExp = agentExpiryBound(ag)
			if s.AgentGate != nil {
				g, gerr := s.gateMint(ctx, *ag, models.AgentMintJWTBearer, audience, grantScope, len(grantScope) > 0, append([]string{}, ag.Scope...))
				if gerr != nil {
					return TokenResponse{}, gerr
				}
				gated = g
				grantScope = g.Scopes
			}
		}
	}
	bearerExp := capExpiry(now.Add(s.Cfg.AccessTokenTTL), agentExp)
	jtiOut := ulid.New().String()
	accessClaims := jwt.Claims{
		Iss:      s.Cfg.Issuer,
		Sub:      userID.String(),
		Aud:      audience,
		Exp:      bearerExp.Unix(),
		Iat:      now.Unix(),
		Jti:      jtiOut,
		ClientID: req.ClientID,
		Scope:    scopeJoin(grantScope),
		Typ:      jwt.TypeAccessToken,
	}
	bearerMeta := map[string]any{
		"issuer":   claims.Iss,
		"subject":  claims.Sub,
		"resource": req.Resource,
		"scope":    grantScope,
		"jti":      jtiOut,
		"grant":    models.GrantTypeJWTBearer,
	}
	if c := agentPolicyClaim(gated); c != nil {
		accessClaims.Extra = map[string]any{"agent_policy": c}
	}
	addAgentPolicy(nil, bearerMeta, gated)
	if herr := s.applyOnTokenIssued(ctx, &accessClaims); herr != nil {
		return TokenResponse{}, herr
	}
	access, aerr := s.issueAccessToken(ctx, req.ClientID, accessClaims)
	if aerr != nil {
		return TokenResponse{}, fmt.Errorf("sign jwt-bearer token: %w", aerr)
	}
	s.Audit.EmitAudit(ctx, "jwt_bearer.token_minted", models.TargetRef{Type: "user", ID: userID.String()}, bearerMeta)
	return TokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(bearerExp.Sub(now).Seconds()),
		Scope:       scopeJoin(grantScope),
	}, nil
}

// auditClaimsDenied records a required-claims denial with the issuer and failed claim names, never
// their values.
func (s *Service) auditClaimsDenied(ctx context.Context, req TokenRequest, issuer string, failed []string) {
	meta := map[string]any{"issuer": issuer, "failed_claims": failed, "grant": models.GrantTypeJWTBearer}
	if req.ClientID != "" {
		if ag, err := s.Storage.AgentByClientID(ctx, req.ClientID); err == nil && ag != nil {
			meta["agent_id"] = ag.ID.String()
			meta["agent_name"] = ag.Name
		}
	}
	s.Audit.EmitAudit(ctx, "jwt_bearer.claims_denied", models.TargetRef{Type: "jwt_issuer", ID: issuer}, meta)
}

// jtiReplayCheck records a jti and errors if it was already seen in the replay window. It uses
// JWTBearerStorage when available, else an in-process map that does not survive restarts.
func (s *Service) jtiReplayCheck(ctx context.Context, jti string, expiresAt time.Time) error {
	if s.jwtBearerStorage != nil {
		return s.jwtBearerStorage.InsertJTI(ctx, jti, expiresAt)
	}
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

// findTrustedIssuer returns the configured TrustedJWTIssuer for issuer, or false.
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

type jwksEntry struct {
	Kid string
	Alg string
	Key crypto.PublicKey
}

// clientJWKS returns the parsed keys of a private_key_jwt client, from inline jwks or jwks_uri.
func (s *Service) clientJWKS(client *models.OAuthClient) ([]jwksEntry, error) {
	if len(client.Jwks) > 0 {
		return parseJWKSBytes(client.Jwks)
	}
	if client.JwksURI != "" {
		return s.jwks.Fetch(context.Background(), client.JwksURI)
	}
	return nil, errors.New("client has no jwks_uri or inline jwks")
}

// trustedIssuerJWKS fetches and caches the JWKS of a TrustedJWTIssuer.
func (s *Service) trustedIssuerJWKS(issuer TrustedJWTIssuer) ([]jwksEntry, error) {
	return s.jwks.Fetch(context.Background(), issuer.JWKSURL)
}

// parseJWKSBytes parses a JWKS document. Keys with use "sig" or no use are kept; encryption keys are skipped.
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
			pub = jwksEd25519PublicKey(keyBytes)
			alg = "EdDSA"
		default:
			continue
		}
		out = append(out, jwksEntry{Kid: base.Kid, Alg: alg, Key: pub})
	}
	// A document with keys that yields none is a parse failure, not an empty set. It stays out of the
	// cache and is visible to the operator.
	if len(out) == 0 && len(doc.Keys) > 0 {
		return nil, fmt.Errorf("parse jwks: none of %d keys could be parsed", len(doc.Keys))
	}
	return out, nil
}

type jwksEd25519PublicKey []byte

// verifyWithJWKS tries each matching key until one verifies. A kid in the header restricts the keys tried.
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

// verifySig dispatches to the crypto primitive for alg.
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
		return verifyECDSASig(ecKey, digest, sig, 32)
	case "ES384":
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		h := sha512.New384()
		h.Write(signingInput)
		digest := h.Sum(nil)
		return verifyECDSASig(ecKey, digest, sig, 48)
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

// verifyECDSASig checks an ECDSA signature over digest. JOSE uses fixed-length R||S (RFC 7518
// section 3.4); ASN.1 DER is still accepted.
func verifyECDSASig(pub *ecdsa.PublicKey, digest, sig []byte, size int) bool {
	if len(sig) == 2*size {
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(pub, digest, r, s)
	}
	return ecdsa.VerifyASN1(pub, digest, sig)
}

// verifyEd25519Raw verifies an Ed25519 signature for a raw 32-byte key.
func verifyEd25519Raw(pub jwksEd25519PublicKey, msg, sig []byte) bool {
	if len(pub) != 32 || len(sig) != 64 {
		return false
	}
	return verifyEd25519Impl(pub, msg, sig)
}

func jwtStringIn(s string, list []string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
