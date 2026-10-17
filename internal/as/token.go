package as

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// token.go holds the token endpoint multiplexer and the authorization_code and refresh_token
// grants. The client_credentials and token-exchange grants live in token_v34.go.

// TokenRequest is the parsed form body of POST /oauth/token plus the authenticated client.
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

	// AuthorizationDetails is the raw RFC 9396 parameter. On the code and refresh grants it may narrow
	// what is carried.
	AuthorizationDetails string

	// DPoPProof is the raw DPoP request header. When DPoP is enabled the token endpoint verifies it
	// and binds the access token to the proof key via cnf.jkt (RFC 7800, RFC 9449).
	DPoPProof string

	// HTTPMethod and HTTPURL are passed to the DPoP verifier to check htm and htu. The handler fills
	// them from the request.
	HTTPMethod string
	HTTPURL    string

	// ClientAssertionType and ClientAssertion carry the RFC 7523 section 2.2 parameters. A JWT bearer
	// type routes to AuthenticateClientJWT instead of the client_secret check.
	ClientAssertionType string
	ClientAssertion     string

	// Assertion is the external JWT for the jwt-bearer grant (RFC 7523 section 2.1).
	Assertion string
}

// TokenResponse is the JSON body returned by /oauth/token. IssuedTokenType is set only for RFC 8693
// exchanges.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	Scope           string `json:"scope"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`

	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`

	// IDToken is the OpenID Connect ID token, present when the grant carries the openid scope.
	IDToken string `json:"id_token,omitempty"`
}

// ExchangeAuthorizationCode redeems a one-time code for an access and refresh token pair. It
// enforces PKCE S256, redirect_uri equality, audience binding (RFC 8707) and client authentication.
func (s *Service) ExchangeAuthorizationCode(ctx context.Context, req TokenRequest) (resp TokenResponse, err error) {
	if s == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	ctx, span, timer := s.startTokenSpan(ctx, "authorization_code")
	defer func() { s.finishTokenSpan(span, timer, "authorization_code", err) }()
	var client *models.OAuthClient
	client, err = s.AuthenticateClientFromRequest(ctx, req, s.tokenEndpointURL())
	if err != nil {
		return TokenResponse{}, err
	}
	if req.Code == "" {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	if req.CodeVerifier == "" {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	codeKey := codeStorageKey(req.Code)
	codeRow, err := s.Storage.ConsumeAuthorizationCode(ctx, codeKey)
	if err != nil {
		// A code that cannot be consumed may be a replay: revoke what was already issued from it (RFC
		// 6749 section 4.1.2).
		s.handleCodeReplay(ctx, codeKey)
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if codeRow.ClientID != client.ClientID {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if !codeRow.ExpiresAt.After(time.Now()) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	loopbackMatch := s.Cfg.ClientCompat.LoopbackAnyPort && s.loopbackEquivalent(req.RedirectURI, codeRow.RedirectURI)
	if req.RedirectURI == "" || (req.RedirectURI != codeRow.RedirectURI && !loopbackMatch) {
		return TokenResponse{}, models.ErrOAuthRedirectURIMismatch
	}
	// PKCE S256: challenge = base64url(sha256(verifier)).
	if codeRow.CodeChallengeMethod != "S256" {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	// The challenge comparison is constant time, so timing cannot act as an oracle (security re-audit L2).
	computed := crypto.CodeChallenge(req.CodeVerifier)
	if subtle.ConstantTimeCompare([]byte(computed), []byte(codeRow.CodeChallenge)) != 1 {
		return TokenResponse{}, models.ErrOAuthPKCEMismatch
	}
	_, audience, err := s.resolveResource(codeRow.Resource)
	if err != nil {
		return TokenResponse{}, err
	}
	scope := codeRow.Scope
	details, err := s.narrowAuthorizationDetails(client, req.AuthorizationDetails, codeRow.AuthorizationDetails)
	if err != nil {
		return TokenResponse{}, err
	}
	jkt, err := s.dpopThumbprintForRequest(req)
	if err != nil {
		return TokenResponse{}, err
	}
	return s.mintAccessAndRefresh(ctx, mintInput{
		ClientID:             client.ClientID,
		UserID:               &codeRow.UserID,
		Scope:                scope,
		Resource:             audience,
		DPoPJKT:              jkt,
		AuthorizationDetails: details,
		AuthCodeHash:         codeKey,
		GrantExpiry:          splitGrantExpiry(req.Code),
		AuthTime:             codeRow.AuthTime,
		ACR:                  codeRow.ACR,
		AMR:                  codeRow.AMR,
		Nonce:                codeRow.Nonce,
		SessionID:            s.codeSession(ctx, codeKey),
	})
}

// RefreshAccessToken rotates a refresh token and returns a new pair. Presenting an already-rotated
// token revokes the whole family (RFC 9700 section 4.14).
func (s *Service) RefreshAccessToken(ctx context.Context, req TokenRequest) (resp TokenResponse, err error) {
	if s == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	ctx, span, timer := s.startTokenSpan(ctx, "refresh_token")
	defer func() { s.finishTokenSpan(span, timer, "refresh_token", err) }()
	var client *models.OAuthClient
	client, err = s.AuthenticateClientFromRequest(ctx, req, s.tokenEndpointURL())
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
		// Reuse of a rotated token revokes the entire rotation family (RFC 9700 section 4.14) and is refused.
		_ = s.Storage.RevokeRefreshTokenFamily(ctx, rt.FamilyID, "reuse detected")
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if !rt.ExpiresAt.After(time.Now()) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	resource := rt.Resource
	if req.Resource != "" && !s.resourceMatchesGrant(req.Resource, resource) {
		return TokenResponse{}, models.ErrOAuthInvalidResource
	}
	// Requested scope must be a subset of the refresh token's scope. Empty means the same scope (RFC
	// 6749 section 6).
	scope, err := s.narrowRefreshScopes(req.Scope, rt.Scope)
	if err != nil {
		return TokenResponse{}, err
	}
	// RFC 9449 section 8: a refresh token of a DPoP-bound grant stays bound to its key. The proof is
	// verified before the token is consumed, so a bad proof does not burn it, and the token is never
	// downgraded to Bearer.
	jkt, err := s.dpopThumbprintForRequest(req)
	if err != nil {
		return TokenResponse{}, err
	}
	if rt.DPoPJKT != "" {
		if jkt == "" || !jktEqual(jkt, rt.DPoPJKT) {
			if jkt == "" {
				return TokenResponse{}, fmt.Errorf("%w: refresh token is DPoP-bound, proof required", ErrDPoPInvalid)
			}
			return TokenResponse{}, fmt.Errorf("%w: proof key does not match the bound key", ErrDPoPInvalid)
		}
	}
	details, err := s.narrowAuthorizationDetails(client, req.AuthorizationDetails, rt.AuthorizationDetails)
	if err != nil {
		return TokenResponse{}, err
	}
	// The old refresh token is revoked before the new pair is issued, so a crash mid-mint cannot leave
	// both alive. A lost race on the revoke counts as reuse.
	if err := s.Storage.RevokeRefreshToken(ctx, hash, "rotated"); err != nil {
		if errors.Is(err, models.ErrStorageNotFound) {
			_ = s.Storage.RevokeRefreshTokenFamily(ctx, rt.FamilyID, "reuse detected")
			return TokenResponse{}, models.ErrOAuthInvalidGrant
		}
		return TokenResponse{}, fmt.Errorf("revoke prior refresh: %w", err)
	}
	return s.mintAccessAndRefresh(ctx, mintInput{
		ClientID:             client.ClientID,
		UserID:               rt.UserID,
		Scope:                scope,
		Resource:             resource,
		FamilyID:             &rt.FamilyID,
		GrantExpiry:          splitGrantExpiry(req.RefreshToken),
		DPoPJKT:              jkt,
		AuthorizationDetails: details,
		// The authentication context carries forward unchanged: a refresh never advances auth_time.
		AuthTime:  rt.AuthTime,
		ACR:       rt.ACR,
		AMR:       rt.AMR,
		SessionID: s.familySession(ctx, rt.FamilyID),
	})
}

// mintInput bundles the parameters for one access and refresh token issuance.
type mintInput struct {
	ClientID string
	UserID   *models.ULID
	Scope    []string
	Resource string
	FamilyID *models.ULID // non-nil when continuing a rotation family
	// DPoPJKT, when set, embeds an RFC 7800 cnf.jkt claim in the access token. Resource servers then
	// require a proof signed by that key.
	DPoPJKT      string
	AuthCodeHash string
	// GrantExpiry, when non-zero, caps access and refresh token expiry (host-owned consent). It rides
	// in the code and refresh token.
	GrantExpiry          time.Time
	AuthorizationDetails []byte
	// AuthTime, ACR and AMR are the grant's authentication context. They become the auth_time, acr and
	// amr claims when set, and are stored on the refresh token for carry-forward.
	AuthTime time.Time
	ACR      string
	AMR      []string
	// Nonce and SessionID feed the ID token: the authorize nonce and the browser session the grant came from.
	Nonce     string
	SessionID string
}

// mintAccessAndRefresh signs a fresh access token and stores a hashed refresh token in the same
// rotation family.
func (s *Service) mintAccessAndRefresh(ctx context.Context, in mintInput) (TokenResponse, error) {
	now := time.Now().UTC()
	accessExp := now.Add(s.Cfg.AccessTokenTTL)
	if !in.GrantExpiry.IsZero() && in.GrantExpiry.Before(accessExp) {
		accessExp = in.GrantExpiry
	}
	if !accessExp.After(now) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
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
		// Resource servers compare the thumbprint of the inbound DPoP proof key with this cnf.jkt before
		// authorizing the call.
		if claims.Extra == nil {
			claims.Extra = map[string]any{}
		}
		claims.Extra["cnf"] = map[string]string{"jkt": in.DPoPJKT}
		// RFC 9449 section 5: a DPoP-bound access token MUST carry token_type "DPoP", not "Bearer".
		tokenType = "DPoP"
	}
	detailsClaim, err := authorizationDetailsClaim(in.AuthorizationDetails)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("authorization_details claim: %w", err)
	}
	if detailsClaim != nil {
		if claims.Extra == nil {
			claims.Extra = map[string]any{}
		}
		claims.Extra["authorization_details"] = detailsClaim
	}
	setAuthContextClaims(&claims, in.AuthTime, in.ACR, in.AMR)
	if err := s.applyOnTokenIssued(ctx, &claims); err != nil {
		return TokenResponse{}, err
	}
	access, err := s.issueAccessToken(ctx, in.ClientID, claims)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("sign access token: %w", err)
	}
	refreshToken, err := crypto.NewToken()
	if err != nil {
		return TokenResponse{}, fmt.Errorf("mint refresh token: %w", err)
	}
	refreshExp := now.Add(s.Cfg.RefreshTokenTTL)
	if !in.GrantExpiry.IsZero() && in.GrantExpiry.Before(refreshExp) {
		refreshExp = in.GrantExpiry
	}
	refreshToken = withGrantExpiry(refreshToken, in.GrantExpiry)
	refreshHash := crypto.HashToken(refreshToken)
	familyID := ulid.New()
	if in.FamilyID != nil {
		familyID = *in.FamilyID
	}
	rt := models.RefreshToken{
		ID:                   ulid.New(),
		Hash:                 refreshHash,
		FamilyID:             familyID,
		ClientID:             in.ClientID,
		UserID:               in.UserID,
		Scope:                in.Scope,
		Resource:             in.Resource,
		ParentJTI:            jti,
		DPoPJKT:              in.DPoPJKT,
		AuthCodeHash:         in.AuthCodeHash,
		AuthorizationDetails: in.AuthorizationDetails,
		AuthTime:             in.AuthTime,
		ACR:                  in.ACR,
		AMR:                  in.AMR,
		IssuedAt:             now,
		ExpiresAt:            refreshExp,
	}
	if err := s.Storage.InsertRefreshToken(ctx, rt); err != nil {
		return TokenResponse{}, fmt.Errorf("insert refresh token: %w", err)
	}
	resp := TokenResponse{
		AccessToken:          access,
		TokenType:            tokenType,
		ExpiresIn:            int(accessExp.Sub(now).Seconds()),
		RefreshToken:         refreshToken,
		Scope:                scopeJoin(in.Scope),
		AuthorizationDetails: authorizationDetailsRaw(claims.Extra),
	}
	if s.OIDCEnabled() && in.UserID != nil && hasScope(in.Scope, ScopeOpenID) {
		s.linkFamilySession(ctx, familyID, in.SessionID, in.ClientID)
		idToken, err := s.issueIDToken(ctx, idTokenInput{
			ClientID:    in.ClientID,
			UserID:      *in.UserID,
			AccessToken: access,
			Nonce:       in.Nonce,
			SessionID:   in.SessionID,
			AuthTime:    in.AuthTime,
			ACR:         in.ACR,
			AMR:         in.AMR,
		})
		if err != nil {
			return TokenResponse{}, fmt.Errorf("issue id token: %w", err)
		}
		resp.IDToken = idToken
	}
	return resp, nil
}

// AuthenticateClient verifies client credentials. Confidential clients must present a secret
// matching the stored Argon2id hash. Public clients (method none) authenticate by client_id alone
// and rely on PKCE. Successful confidential verifies are cached by client_id, bound to the sha256
// of the secret. Every path that rotates or removes a secret must call InvalidateClientAuthCache.
// Public clients never reach the cache.
func (s *Service) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*models.OAuthClient, error) {
	if s == nil {
		return nil, errors.New("theauth: authorization server not configured")
	}
	if clientID == "" {
		return nil, models.ErrOAuthInvalidClient
	}
	// A cache hit skips both the storage read and the Argon2id verify. Only confidential clients are
	// ever inserted.
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
		ok, err := s.verifyClientSecret(ctx, clientSecret, string(client.ClientSecretHash))
		if errors.Is(err, models.ErrOAuthServerBusy) {
			return nil, err
		}
		if err != nil || !ok {
			// Failures are never cached. Wrong secrets keep paying Argon2id, so the rate limiter can
			// throttle them, and a rotated secret cannot be poisoned by an old entry.
			return nil, models.ErrOAuthInvalidClient
		}
		s.clientAuthCache.Put(clientID, clientSecret, client)
		s.updateCacheSizeGauge()
		return client, nil
	case models.ClientAuthPrivateKeyJWT, models.ClientAuthClientSecretJWT:
		// JWT client authentication goes through AuthenticateClientJWT. This legacy path carries no
		// assertion, so it fails.
		return nil, models.ErrOAuthInvalidClient
	default:
		return nil, models.ErrOAuthInvalidClient
	}
}

// AuthenticateClientFromRequest routes to AuthenticateClientJWT when the request carries a
// client_assertion_type, and to AuthenticateClient otherwise.
func (s *Service) AuthenticateClientFromRequest(ctx context.Context, req TokenRequest, tokenEndpointURL string) (*models.OAuthClient, error) {
	if req.ClientAssertionType == models.ClientAssertionTypeJWTBearer && req.ClientAssertion != "" {
		return s.AuthenticateClientJWT(ctx, req.ClientID, req.ClientAssertion, tokenEndpointURL)
	}
	return s.AuthenticateClient(ctx, req.ClientID, req.ClientSecret)
}
