package theauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/jwt"
	"github.com/glincker/theauth-go/internal/ulid"
)

// service_token.go: the OAuth 2.1 token endpoint multiplexer plus the
// authorization_code and refresh_token grant implementations. Per phase 1 + 2
// scope, client_credentials and urn:ietf:params:oauth:grant-type:token-exchange
// are explicitly not implemented; they ship in phase 3 + 4.

// TokenRequest is the parsed form-encoded body of a POST /oauth/token call,
// plus the authenticated client extracted from the request line / headers.
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
}

// TokenResponse is the JSON body emitted by /oauth/token on success.
// IssuedTokenType is populated by the RFC 8693 token-exchange grant (phase 4)
// per RFC 8693 section 2.2.1; omitted on other grants.
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
func (a *TheAuth) ExchangeAuthorizationCode(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	if a.as == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	client, err := a.authenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	if req.Code == "" {
		return TokenResponse{}, ErrOAuthInvalidRequest
	}
	if req.CodeVerifier == "" {
		return TokenResponse{}, ErrOAuthInvalidRequest
	}
	codeRow, err := a.as.storage.ConsumeAuthorizationCode(ctx, req.Code)
	if err != nil {
		return TokenResponse{}, ErrOAuthInvalidGrant
	}
	if codeRow.ClientID != client.ClientID {
		return TokenResponse{}, ErrOAuthInvalidGrant
	}
	if !codeRow.ExpiresAt.After(time.Now()) {
		return TokenResponse{}, ErrOAuthInvalidGrant
	}
	if req.RedirectURI == "" || req.RedirectURI != codeRow.RedirectURI {
		return TokenResponse{}, ErrOAuthRedirectURIMismatch
	}
	// PKCE S256: challenge = base64url(sha256(verifier)).
	if codeRow.CodeChallengeMethod != "S256" {
		return TokenResponse{}, ErrOAuthInvalidGrant
	}
	if crypto.CodeChallenge(req.CodeVerifier) != codeRow.CodeChallenge {
		return TokenResponse{}, ErrOAuthPKCEMismatch
	}
	if _, ok := a.resourceByIdentifier(codeRow.Resource); !ok {
		return TokenResponse{}, ErrOAuthInvalidResource
	}
	scope := codeRow.Scope
	return a.mintAccessAndRefresh(ctx, mintInput{
		ClientID: client.ClientID,
		UserID:   &codeRow.UserID,
		Scope:    scope,
		Resource: codeRow.Resource,
	})
}

// RefreshAccessToken rotates a refresh token, returning a new access token +
// refresh token pair. The old refresh token is revoked; presenting it again
// triggers family-wide revocation per RFC 9700 section 4.14.
func (a *TheAuth) RefreshAccessToken(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	if a.as == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	client, err := a.authenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	if req.RefreshToken == "" {
		return TokenResponse{}, ErrOAuthInvalidRequest
	}
	hash := crypto.HashToken(req.RefreshToken)
	rt, err := a.as.storage.RefreshTokenByHash(ctx, hash)
	if err != nil {
		return TokenResponse{}, ErrOAuthInvalidGrant
	}
	if rt.ClientID != client.ClientID {
		return TokenResponse{}, ErrOAuthInvalidGrant
	}
	if rt.RevokedAt != nil {
		// Re-use detection: prior revoked token presented. Revoke the entire
		// rotation family (RFC 9700 section 4.14) and reject.
		_ = a.as.storage.RevokeRefreshTokenFamily(ctx, rt.FamilyID, "reuse detected")
		return TokenResponse{}, ErrOAuthInvalidGrant
	}
	if !rt.ExpiresAt.After(time.Now()) {
		return TokenResponse{}, ErrOAuthInvalidGrant
	}
	resource := rt.Resource
	if req.Resource != "" {
		if req.Resource != resource {
			return TokenResponse{}, ErrOAuthInvalidResource
		}
	}
	// Narrowing: requested scope (if any) must be a subset of the existing
	// refresh token's scope. Empty means "same scope" per RFC 6749 section 6.
	scope := rt.Scope
	if len(req.Scope) > 0 {
		if !scopeSubset(req.Scope, rt.Scope) {
			return TokenResponse{}, ErrOAuthInvalidScope
		}
		scope = req.Scope
	}
	// Revoke the old refresh token before issuing the new pair, so a crash
	// mid-mint cannot leave both alive (the new mint is idempotent on its
	// fresh family ID).
	if err := a.as.storage.RevokeRefreshToken(ctx, hash, "rotated"); err != nil {
		return TokenResponse{}, fmt.Errorf("revoke prior refresh: %w", err)
	}
	return a.mintAccessAndRefresh(ctx, mintInput{
		ClientID: client.ClientID,
		UserID:   rt.UserID,
		Scope:    scope,
		Resource: resource,
		FamilyID: &rt.FamilyID,
	})
}

// mintInput bundles the parameters for an access + refresh token issuance.
type mintInput struct {
	ClientID string
	UserID   *ULID
	Scope    []string
	Resource string
	FamilyID *ULID // non-nil when continuing a rotation family
}

// mintAccessAndRefresh signs a fresh access token JWT and stores a fresh
// hashed refresh token in the same rotation family.
func (a *TheAuth) mintAccessAndRefresh(ctx context.Context, in mintInput) (TokenResponse, error) {
	signingKey, priv, err := a.currentSigningKey()
	if err != nil {
		return TokenResponse{}, err
	}
	now := time.Now().UTC()
	accessExp := now.Add(a.as.cfg.AccessTokenTTL)
	jti := ulid.New().String()
	sub := ""
	if in.UserID != nil {
		sub = in.UserID.String()
	}
	claims := jwt.Claims{
		Iss:      a.as.cfg.Issuer,
		Sub:      sub,
		Aud:      in.Resource,
		Exp:      accessExp.Unix(),
		Iat:      now.Unix(),
		Jti:      jti,
		ClientID: in.ClientID,
		Scope:    scopeJoin(in.Scope),
		Typ:      jwt.TypeAccessToken,
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
	rt := RefreshToken{
		ID:        ulid.New(),
		Hash:      refreshHash,
		FamilyID:  familyID,
		ClientID:  in.ClientID,
		UserID:    in.UserID,
		Scope:     in.Scope,
		Resource:  in.Resource,
		ParentJTI: jti,
		IssuedAt:  now,
		ExpiresAt: now.Add(a.as.cfg.RefreshTokenTTL),
	}
	if err := a.as.storage.InsertRefreshToken(ctx, rt); err != nil {
		return TokenResponse{}, fmt.Errorf("insert refresh token: %w", err)
	}
	return TokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int(a.as.cfg.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
		Scope:        scopeJoin(in.Scope),
	}, nil
}

// authenticateClient verifies client credentials. Confidential clients
// (token_endpoint_auth_method = client_secret_basic | client_secret_post)
// MUST supply a non-empty secret matching the stored Argon2id hash. Public
// clients (token_endpoint_auth_method = none) authenticate by client_id
// alone and rely on PKCE for proof of possession.
//
// Hot-path optimization: a successful Argon2id verify is cached on
// a.as.clientAuthCache, keyed by client_id and bound to the sha256 of the
// presented secret. The cache is bounded (DefaultMaxEntries) and entries
// expire after DefaultTTL. Every code path that rotates or removes the
// stored client_secret_hash MUST invalidate via invalidateClientAuthCache;
// see the contract comment on asState.clientAuthCache. The public-client
// path (ClientAuthNone) does not pay Argon2id at all and is therefore not
// cached: the storage lookup it does is already cheap and skipping the
// cache avoids a code path that would have to teach the cache "this entry
// has no secret".
func (a *TheAuth) authenticateClient(ctx context.Context, clientID, clientSecret string) (*OAuthClient, error) {
	if a.as == nil {
		return nil, errors.New("theauth: authorization server not configured")
	}
	if clientID == "" {
		return nil, ErrOAuthInvalidClient
	}
	// Fast path: cache hit returns the verified client snapshot without the
	// storage round trip and without the Argon2id verify. The cache only
	// stores successful confidential-client verifications; a public client
	// (ClientAuthNone) is never inserted, so a hit here implies we have a
	// confidential client and the presented secret matches the digest we
	// stored at insert.
	if clientSecret != "" {
		if cached, ok := a.as.clientAuthCache.Get(clientID, clientSecret); ok && cached != nil {
			return cached, nil
		}
	}
	client, err := a.as.storage.OAuthClientByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrOAuthInvalidClient
	}
	switch client.TokenEndpointAuthMethod {
	case ClientAuthNone:
		if clientSecret != "" {
			return nil, ErrOAuthInvalidClient
		}
		return client, nil
	case ClientAuthSecretBasic, ClientAuthSecretPost, "":
		if clientSecret == "" || len(client.ClientSecretHash) == 0 {
			return nil, ErrOAuthInvalidClient
		}
		ok, err := crypto.VerifyPassword(clientSecret, string(client.ClientSecretHash))
		if err != nil || !ok {
			// Failures are never cached: an attacker presenting a wrong
			// secret must keep paying Argon2id on every attempt so the
			// rate limiter (middleware_ratelimit.go) can throttle them,
			// and a legitimate client whose secret was just rotated
			// cannot have a wrong-secret entry poisoning the cache.
			return nil, ErrOAuthInvalidClient
		}
		a.as.clientAuthCache.Put(clientID, clientSecret, client)
		return client, nil
	default:
		return nil, ErrOAuthInvalidClient
	}
}
