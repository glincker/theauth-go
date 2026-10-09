package as

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/cimd"
	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// dcr.go: RFC 7591 dynamic client registration.
//
// Two modes:
//
//	bearer-gated (default): the caller MUST present a Bearer token on
//	  POST /oauth/register whose sha256 digest matches one of the
//	  operator-configured AuthorizationServerConfig.RegistrationTokens
//	  entries (constant-time compare). When RegistrationTokens is empty
//	  and AllowAnonymousRegistration is false, every request is denied.
//	  Tightened in security audit H1 (2026-06-20); the legacy phase 1+2
//	  behavior of accepting any non-empty bearer is no longer present.
//	anonymous: enabled via Config.AuthorizationServer.AllowAnonymousRegistration.
//	  Public MCP servers need this; the handler is rate limited to
//	  RegistrationRateLimitPerMinute requests per source IP per minute
//	  (default 1/min, configurable via AS config) and stamps
//	  anonymous_registered = true on the resulting OAuthClient row for
//	  operator auditing (security audit H2, 2026-06-20).

// ClientRegistrationRequest is the parsed JSON body of POST
// /oauth/register. Field names match RFC 7591 client metadata exactly so
// the wire form maps 1:1 onto the struct.
type ClientRegistrationRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	JwksURI                 string   `json:"jwks_uri,omitempty"`
	// Jwks is the RFC 7517 JSON Web Key Set document (inline). Used by JAR
	// (RFC 9101) to verify request object signatures when jwks_uri is not set.
	Jwks            json.RawMessage `json:"jwks,omitempty"`
	SoftwareID      string          `json:"software_id,omitempty"`
	SoftwareVersion string          `json:"software_version,omitempty"`

	// AccessTokenFormat is "jwt" or "opaque"; see Config.TokenPolicy.
	AccessTokenFormat string `json:"access_token_format,omitempty"`
	// AccessTokenSignedResponseAlg picks the JWS alg for JWT access tokens.
	AccessTokenSignedResponseAlg string `json:"access_token_signed_response_alg,omitempty"`
	// AuthorizationDetailsTypes lists the RFC 9396 types the client may
	// request (RFC 9396 section 10).
	AuthorizationDetailsTypes []string `json:"authorization_details_types,omitempty"`
}

// RegisterClient validates the request, mints a client_id (and a secret
// for confidential clients), persists the OAuthClient row, and returns
// the RFC 7591 response body. The plaintext secret is in the return
// value; callers must surface it to the caller exactly once and never
// log it.
func (s *Service) RegisterClient(ctx context.Context, req ClientRegistrationRequest, anonymous bool) (registered models.RegisteredClient, err error) {
	if s == nil {
		return models.RegisteredClient{}, errors.New("theauth: authorization server not configured")
	}
	ctx, span := s.Hooks.StartSpan(ctx, obs.SpanOAuthDCRRegister, obs.BoolAttr("anonymous", anonymous))
	defer func() {
		status := obs.StatusSuccess
		if err != nil {
			status = obs.StatusError
			span.RecordError(err)
			span.SetAttributes(obs.StringAttr(obs.AttrErrorCode, errorCode(err)))
		}
		span.SetAttributes(obs.StringAttr(obs.AttrStatus, string(status)))
		span.End()
	}()
	if anonymous && !s.Cfg.AllowAnonymousRegistration {
		return models.RegisteredClient{}, models.ErrOAuthRegistrationDenied
	}
	if err := validateRegistrationRequest(&req, anonymous); err != nil {
		return models.RegisteredClient{}, err
	}
	if err := s.validateTokenMetadata(req, anonymous); err != nil {
		return models.RegisteredClient{}, err
	}
	clientID := "client-" + ulid.New().String()
	now := time.Now().UTC()
	client := models.OAuthClient{
		ID:                           ulid.New(),
		ClientID:                     clientID,
		ClientName:                   req.ClientName,
		RedirectURIs:                 req.RedirectURIs,
		GrantTypes:                   req.GrantTypes,
		ResponseTypes:                req.ResponseTypes,
		Scope:                        req.Scope,
		TokenEndpointAuthMethod:      req.TokenEndpointAuthMethod,
		ApplicationType:              req.ApplicationType,
		Contacts:                     req.Contacts,
		LogoURI:                      req.LogoURI,
		PolicyURI:                    req.PolicyURI,
		TosURI:                       req.TosURI,
		JwksURI:                      req.JwksURI,
		Jwks:                         []byte(req.Jwks),
		SoftwareID:                   req.SoftwareID,
		SoftwareVersion:              req.SoftwareVersion,
		AccessTokenFormat:            req.AccessTokenFormat,
		AccessTokenSignedResponseAlg: req.AccessTokenSignedResponseAlg,
		AuthorizationDetailsTypes:    req.AuthorizationDetailsTypes,
		AnonymousRegistered:          anonymous,
		CreatedAt:                    now,
		UpdatedAt:                    now,
	}
	resp := models.RegisteredClient{
		ClientID:                     clientID,
		ClientIDIssuedAt:             now.Unix(),
		RedirectURIs:                 req.RedirectURIs,
		GrantTypes:                   req.GrantTypes,
		ResponseTypes:                req.ResponseTypes,
		Scope:                        req.Scope,
		TokenEndpointAuthMethod:      req.TokenEndpointAuthMethod,
		ApplicationType:              req.ApplicationType,
		ClientName:                   req.ClientName,
		Contacts:                     req.Contacts,
		LogoURI:                      req.LogoURI,
		PolicyURI:                    req.PolicyURI,
		TosURI:                       req.TosURI,
		JwksURI:                      req.JwksURI,
		SoftwareID:                   req.SoftwareID,
		SoftwareVersion:              req.SoftwareVersion,
		AccessTokenFormat:            req.AccessTokenFormat,
		AccessTokenSignedResponseAlg: req.AccessTokenSignedResponseAlg,
		AuthorizationDetailsTypes:    req.AuthorizationDetailsTypes,
	}
	if req.TokenEndpointAuthMethod != models.ClientAuthNone {
		secret, err := crypto.NewToken()
		if err != nil {
			return models.RegisteredClient{}, fmt.Errorf("generate client secret: %w", err)
		}
		hash, err := crypto.HashPassword(secret)
		if err != nil {
			return models.RegisteredClient{}, fmt.Errorf("hash client secret: %w", err)
		}
		client.ClientSecretHash = []byte(hash)
		resp.ClientSecret = secret
		// Anonymous clients get a 30-day secret TTL; bearer-gated
		// clients effectively never expire (0 per RFC 7591 means
		// "never").
		if anonymous {
			resp.ClientSecretExpiresAt = now.Add(30 * 24 * time.Hour).Unix()
		}
	}
	stored, err := s.Storage.InsertOAuthClient(ctx, client)
	if err != nil {
		return models.RegisteredClient{}, fmt.Errorf("persist oauth client: %w", err)
	}
	resp.ClientID = stored.ClientID
	return resp, nil
}

// validateRegistrationRequest screens RFC 7591 metadata and applies
// defaults matching the OAuth 2.1 + MCP profile.
func validateRegistrationRequest(req *ClientRegistrationRequest, anonymous bool) error {
	// Determine if authorization_code is in the grant list. When not
	// explicitly set yet, the default is authorization_code + refresh_token
	// (applied below), so redirect_uris is required in that case too.
	requiresRedirectURI := len(req.GrantTypes) == 0
	for _, gt := range req.GrantTypes {
		if gt == models.GrantTypeAuthorizationCode {
			requiresRedirectURI = true
			break
		}
	}
	if requiresRedirectURI && len(req.RedirectURIs) == 0 {
		return wrapInvalidReg("redirect_uris is required for authorization_code clients")
	}
	if anonymous && len(req.RedirectURIs) > 1 {
		// Tight cap matches the anonymous registration policy in spec
		// section 9.10.
		return wrapInvalidReg("anonymous clients may register at most one redirect URI")
	}
	for _, u := range req.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return err
		}
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{models.GrantTypeAuthorizationCode, models.GrantTypeRefreshToken}
	}
	for _, gt := range req.GrantTypes {
		switch gt {
		case models.GrantTypeAuthorizationCode, models.GrantTypeRefreshToken,
			models.GrantTypeClientCredentials, models.GrantTypeTokenExchange,
			models.GrantTypeCIBA, models.GrantTypeDeviceCode:
			// supported
		default:
			return wrapInvalidReg("unsupported grant_type: " + gt)
		}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{models.ResponseTypeCode}
	}
	for _, rt := range req.ResponseTypes {
		if rt != models.ResponseTypeCode {
			return wrapInvalidReg("unsupported response_type: " + rt)
		}
	}
	if req.TokenEndpointAuthMethod == "" {
		if anonymous {
			req.TokenEndpointAuthMethod = models.ClientAuthNone
		} else {
			req.TokenEndpointAuthMethod = models.ClientAuthSecretBasic
		}
	}
	switch req.TokenEndpointAuthMethod {
	case models.ClientAuthSecretBasic, models.ClientAuthSecretPost, models.ClientAuthNone:
	default:
		return wrapInvalidReg("unsupported token_endpoint_auth_method: " + req.TokenEndpointAuthMethod)
	}
	if anonymous && req.TokenEndpointAuthMethod != models.ClientAuthNone {
		// Public clients only for anonymous registration; spec section
		// 9.10.
		return wrapInvalidReg("anonymous clients must use token_endpoint_auth_method=none")
	}
	if req.ApplicationType == "" {
		req.ApplicationType = "web"
	}
	return nil
}

// validateRedirectURI enforces RFC 7591, RFC 8252 and OAuth 2.1 on a
// registered redirect URI. It must parse, be absolute, carry no fragment
// and no userinfo, and use one of:
//
//   - https (any host);
//   - http on a loopback host (localhost, 127.0.0.1, ::1) with any port
//     (RFC 8252 section 7.3);
//   - a private-use scheme in reverse-DNS form (RFC 8252 section 7.1),
//     i.e. the scheme contains a dot, such as com.example.app.
//
// Everything else, notably javascript:, data:, file:, vbscript: and
// dotless custom schemes, is refused so a registered URI can never turn
// the authorization redirect into script execution or local file access.
func validateRedirectURI(raw string) error {
	if err := cimd.ValidateRedirectURI(raw); err != nil {
		return wrapInvalidReg(err.Error())
	}
	return nil
}

// wrapInvalidReg wraps an arbitrary validation message as the RFC 7591
// invalid_client_metadata error code. Handlers map this to 400 with
// {error: "invalid_client_metadata", error_description: <message>}.
func wrapInvalidReg(msg string) error {
	return &models.TheAuthError{Code: "invalid_client_metadata", Message: msg, Inner: models.ErrOAuthInvalidRequest}
}

// validateTokenMetadata vets the access token policy and RAR metadata of a
// registration request. Anonymous registrants may not set them: they pick
// server-side behaviour (key generation, token storage) that only a trusted
// registrant should control.
func (s *Service) validateTokenMetadata(req ClientRegistrationRequest, anonymous bool) error {
	set := req.AccessTokenFormat != "" || req.AccessTokenSignedResponseAlg != "" || len(req.AuthorizationDetailsTypes) > 0
	if !set {
		return nil
	}
	if anonymous {
		return wrapInvalidReg("access token policy and authorization_details_types need an authenticated registration")
	}
	if err := s.ValidateClientTokenPolicy(req.AccessTokenFormat, req.AccessTokenSignedResponseAlg); err != nil {
		return wrapInvalidReg(err.Error())
	}
	if err := s.ValidateClientRARTypes(req.AuthorizationDetailsTypes); err != nil {
		return wrapInvalidReg(err.Error())
	}
	return nil
}
