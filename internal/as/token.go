package as

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/jwt"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
)

// token.go: the OAuth 2.1 token endpoint multiplexer plus the
// authorization_code and refresh_token grant implementations. Per phase
// 1 + 2 scope, client_credentials and
// urn:ietf:params:oauth:grant-type:token-exchange live in token_v34.go
// alongside the agent identity hooks.

// TokenRequest is the parsed form-encoded body of a POST /oauth/token
// call, plus the authenticated client extracted from the request line /
// headers.
type TokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	Code         string
	CodeVerifier string
	RedirectURI  string
	RefreshToken string
	Resource     string
	Scope        []string

	// DPoPProof, when non-empty, is the raw value of the request's DPoP
	// header. When populated and the AS has DPoP enabled, the token
	// endpoint verifies the proof and binds the issued access token to
	// the proof key via cnf.jkt (RFC 7800 + RFC 9449).
	DPoPProof string

	// HTTPMethod + HTTPURL are the request method + canonical URL
	// passed through to the DPoP verifier so it can check htm / htu.
	// The handler populates these from the incoming http.Request; tests
	// supply them directly.
	HTTPMethod string
	HTTPURL    string
}

// TokenResponse is the JSON body emitted by /oauth/token on success.
// IssuedTokenType is populated by the RFC 8693 token-exchange grant
// (phase 4) per RFC 8693 section 2.2.1; omitted on other grants.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	Scope           string `json:"scope"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

// ExchangeAuthorizationCode redeems a one-time authorization code for an
// access token + refresh token pair. Enforces PKCE S256, redirect_uri
// equality, audience binding (RFC 8707), and client authentication.
func (s *Service) ExchangeAuthorizationCode(ctx context.Context, req TokenRequest) (resp TokenResponse, err error) {
	if s == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	ctx, span, timer := s.startTokenSpan(ctx, "authorization_code")
	defer func() { s.finishTokenSpan(span, timer, "authorization_code", err) }()
	var client *models.OAuthClient
	client, err = s.AuthenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	if req.Code == "" {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	if req.CodeVerifier == "" {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	codeRow, err := s.Storage.ConsumeAuthorizationCode(ctx, req.Code)
	if err != nil {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if codeRow.ClientID != client.ClientID {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if !codeRow.ExpiresAt.After(time.Now()) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if req.RedirectURI == "" || req.RedirectURI != codeRow.RedirectURI {
		return TokenResponse{}, models.ErrOAuthRedirectURIMismatch
	}
	// PKCE S256: challenge = base64url(sha256(verifier)).
	if codeRow.CodeChallengeMethod != "S256" {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if crypto.CodeChallenge(req.CodeVerifier) != codeRow.CodeChallenge {
		return TokenResponse{}, models.ErrOAuthPKCEMismatch
	}
	if _, ok := s.ResourceByIdentifier(codeRow.Resource); !ok {
		return TokenResponse{}, models.ErrOAuthInvalidResource
	}
	scope := codeRow.Scope
	jkt, err := s.dpopThumbprintForRequest(req)
	if err != nil {
		return TokenResponse{}, err
	}
	return s.mintAccessAndRefresh(ctx, mintInput{
		ClientID: client.ClientID,
		UserID:   &codeRow.UserID,
		Scope:    scope,
		Resource: codeRow.Resource,
		DPoPJKT:  jkt,
	})
}

// RefreshAccessToken rotates a refresh token, returning a new access
// token + refresh token pair. The old refresh token is revoked;
// presenting it again triggers family-wide revocation per RFC 9700
// section 4.14.
func (s *Service) RefreshAccessToken(ctx context.Context, req TokenRequest) (resp TokenResponse, err error) {
	if s == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	ctx, span, timer := s.startTokenSpan(ctx, "refresh_token")
	defer func() { s.finishTokenSpan(span, timer, "refresh_token", err) }()
	var client *models.OAuthClient
	client, err = s.AuthenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	if req.RefreshToken == "" {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	hash := crypto.HashToken(req.RefreshToken)
	rt, err := s.Storage.RefreshTokenByHash(ctx, hash)
	if err != nil {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if rt.ClientID != client.ClientID {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if rt.RevokedAt != nil {
		// Re-use detection: prior revoked token presented. Revoke the
		// entire rotation family (RFC 9700 section 4.14) and reject.
		_ = s.Storage.RevokeRefreshTokenFamily(ctx, rt.FamilyID, "reuse detected")
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if !rt.ExpiresAt.After(time.Now()) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	resource := rt.Resource
	if req.Resource != "" {
		if req.Resource != resource {
			return TokenResponse{}, models.ErrOAuthInvalidResource
		}
	}
	// Narrowing: requested scope (if any) must be a subset of the
	// existing refresh token's scope. Empty means "same scope" per RFC
	// 6749 section 6.
	scope := rt.Scope
	if len(req.Scope) > 0 {
		if !scopeSubset(req.Scope, rt.Scope) {
			return TokenResponse{}, models.ErrOAuthInvalidScope
		}
		scope = req.Scope
	}
	// Revoke the old refresh token before issuing the new pair, so a
	// crash mid-mint cannot leave both alive (the new mint is idempotent
	// on its fresh family ID).
	if err := s.Storage.RevokeRefreshToken(ctx, hash, "rotated"); err != nil {
		return TokenResponse{}, fmt.Errorf("revoke prior refresh: %w", err)
	}
	jkt, err := s.dpopThumbprintForRequest(req)
	if err != nil {
		return TokenResponse{}, err
	}
	return s.mintAccessAndRefresh(ctx, mintInput{
		ClientID: client.ClientID,
		UserID:   rt.UserID,
		Scope:    scope,
		Resource: resource,
		FamilyID: &rt.FamilyID,
		DPoPJKT:  jkt,
	})
}

// mintInput bundles the parameters for an access + refresh token
// issuance.
type mintInput struct {
	ClientID string
	UserID   *models.ULID
	Scope    []string
	Resource string
	FamilyID *models.ULID // non-nil when continuing a rotation family
	// DPoPJKT, when non-empty, embeds an RFC 7800 cnf.jkt confirmation
	// claim in the access token, binding the token to the DPoP proof
	// key. Resource servers MUST then require an inbound DPoP proof
	// signed by the matching key on every protected call.
	DPoPJKT string
}

// mintAccessAndRefresh signs a fresh access token JWT and stores a fresh
// hashed refresh token in the same rotation family.
func (s *Service) mintAccessAndRefresh(ctx context.Context, in mintInput) (TokenResponse, error) {
	signingKey, priv, err := s.CurrentSigningKey()
	if err != nil {
		return TokenResponse{}, err
	}
	now := time.Now().UTC()
	accessExp := now.Add(s.Cfg.AccessTokenTTL)
	jti := ulid.New().String()
	sub := ""
	if in.UserID != nil {
		sub = in.UserID.String()
	}
	claims := jwt.Claims{
		Iss:      s.Cfg.Issuer,
		Sub:      sub,
		Aud:      in.Resource,
		Exp:      accessExp.Unix(),
		Iat:      now.Unix(),
		Jti:      jti,
		ClientID: in.ClientID,
		Scope:    scopeJoin(in.Scope),
		Typ:      jwt.TypeAccessToken,
	}
	tokenType := "Bearer"
	if in.DPoPJKT != "" {
		// RFC 7800 confirmation claim: resource servers compare the
		// thumbprint of the inbound DPoP proof key against this value
		// before authorizing the call.
		if claims.Extra == nil {
			claims.Extra = map[string]any{}
		}
		claims.Extra["cnf"] = map[string]string{"jkt": in.DPoPJKT}
		// RFC 9449 section 5: the token_type emitted alongside a
		// DPoP-bound access token MUST be "DPoP", not "Bearer". The
		// resource server keys its dispatching logic off of this.
		tokenType = "DPoP"
	}
	access, err := jwt.Sign(claims, signingKey.KID, priv)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("sign access token: %w", err)
	}
	refreshToken, err := crypto.NewToken()
	if err != nil {
		return TokenResponse{}, fmt.Errorf("mint refresh token: %w", err)
	}
	refreshHash := crypto.HashToken(refreshToken)
	familyID := ulid.New()
	if in.FamilyID != nil {
		familyID = *in.FamilyID
	}
	rt := models.RefreshToken{
		ID:        ulid.New(),
		Hash:      refreshHash,
		FamilyID:  familyID,
		ClientID:  in.ClientID,
		UserID:    in.UserID,
		Scope:     in.Scope,
		Resource:  in.Resource,
		ParentJTI: jti,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.Cfg.RefreshTokenTTL),
	}
	if err := s.Storage.InsertRefreshToken(ctx, rt); err != nil {
		return TokenResponse{}, fmt.Errorf("insert refresh token: %w", err)
	}
	return TokenResponse{
		AccessToken:  access,
		TokenType:    tokenType,
		ExpiresIn:    int(s.Cfg.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
		Scope:        scopeJoin(in.Scope),
	}, nil
}

// AuthenticateClient verifies client credentials. Confidential clients
// (token_endpoint_auth_method = client_secret_basic | client_secret_post)
// MUST supply a non-empty secret matching the stored Argon2id hash.
// Public clients (token_endpoint_auth_method = none) authenticate by
// client_id alone and rely on PKCE for proof of possession.
//
// Hot-path optimization: a successful Argon2id verify is cached on
// s.clientAuthCache, keyed by client_id and bound to the sha256 of the
// presented secret. The cache is bounded (DefaultMaxEntries) and entries
// expire after DefaultTTL. Every code path that rotates or removes the
// stored client_secret_hash MUST invalidate via
// Service.InvalidateClientAuthCache. The public-client path
// (ClientAuthNone) does not pay Argon2id at all and is therefore not
// cached.
func (s *Service) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*models.OAuthClient, error) {
	if s == nil {
		return nil, errors.New("theauth: authorization server not configured")
	}
	if clientID == "" {
		return nil, models.ErrOAuthInvalidClient
	}
	// Fast path: cache hit returns the verified client snapshot without
	// the storage round trip and without the Argon2id verify. The cache
	// only stores successful confidential-client verifications; a public
	// client (ClientAuthNone) is never inserted, so a hit here implies
	// we have a confidential client and the presented secret matches
	// the digest we stored at insert.
	if clientSecret != "" {
		if cached, ok := s.clientAuthCache.Get(clientID, clientSecret); ok && cached != nil {
			s.observeCacheHit("oauth_client")
			return cached, nil
		}
		s.observeCacheMiss("oauth_client")
	}
	client, err := s.ResolveClient(ctx, clientID)
	if err != nil {
		return nil, models.ErrOAuthInvalidClient
	}
	switch client.TokenEndpointAuthMethod {
	case models.ClientAuthNone:
		if clientSecret != "" {
			return nil, models.ErrOAuthInvalidClient
		}
		return client, nil
	case models.ClientAuthSecretBasic, models.ClientAuthSecretPost, "":
		if clientSecret == "" || len(client.ClientSecretHash) == 0 {
			return nil, models.ErrOAuthInvalidClient
		}
		ok, err := crypto.VerifyPassword(clientSecret, string(client.ClientSecretHash))
		if err != nil || !ok {
			// Failures are never cached: an attacker presenting a wrong
			// secret must keep paying Argon2id on every attempt so the
			// rate limiter can throttle them, and a legitimate client
			// whose secret was just rotated cannot have a wrong-secret
			// entry poisoning the cache.
			return nil, models.ErrOAuthInvalidClient
		}
		s.clientAuthCache.Put(clientID, clientSecret, client)
		s.updateCacheSizeGauge()
		return client, nil
	default:
		return nil, models.ErrOAuthInvalidClient
	}
}
