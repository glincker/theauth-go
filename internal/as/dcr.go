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

// dcr.go implements RFC 7591 dynamic client registration in two modes. Bearer-gated (default): the
// caller must present a token whose sha256 digest matches an operator-configured RegistrationTokens
// entry; with none configured every request is denied (security audit H1). Anonymous
// (AllowAnonymousRegistration): rate limited per IP, and the resulting client is stamped
// anonymous_registered for audit (security audit H2).

// ClientRegistrationRequest is the parsed JSON body of POST /oauth/register, with RFC 7591 field names.
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
	// Jwks is the inline RFC 7517 key set. JAR (RFC 9101) uses it when jwks_uri is not set.
	Jwks            json.RawMessage `json:"jwks,omitempty"`
	SoftwareID      string          `json:"software_id,omitempty"`
	SoftwareVersion string          `json:"software_version,omitempty"`

	AccessTokenFormat            string   `json:"access_token_format,omitempty"`
	AccessTokenSignedResponseAlg string   `json:"access_token_signed_response_alg,omitempty"`
	AuthorizationDetailsTypes    []string `json:"authorization_details_types,omitempty"`

	SubjectType                      string   `json:"subject_type,omitempty"`
	PostLogoutRedirectURIs           []string `json:"post_logout_redirect_uris,omitempty"`
	BackchannelLogoutURI             string   `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired bool     `json:"backchannel_logout_session_required,omitempty"`
}

// RegisterClient validates the request, mints a client_id (and a secret for confidential clients),
// persists the client, and returns the RFC 7591 response. The plaintext secret is returned once and
// must never be logged.
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
	if err := s.validateOIDCMetadata(req, anonymous); err != nil {
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

		SubjectType:                      req.SubjectType,
		PostLogoutRedirectURIs:           req.PostLogoutRedirectURIs,
		BackchannelLogoutURI:             req.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired: req.BackchannelLogoutSessionRequired,

		AnonymousRegistered: anonymous,
		CreatedAt:           now,
		UpdatedAt:           now,
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

		SubjectType:                      req.SubjectType,
		PostLogoutRedirectURIs:           req.PostLogoutRedirectURIs,
		BackchannelLogoutURI:             req.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired: req.BackchannelLogoutSessionRequired,
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
		// Anonymous clients get a 30-day secret TTL. Bearer-gated clients never expire (RFC 7591 uses 0 for that).
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

// validateRegistrationRequest screens RFC 7591 metadata and applies the OAuth 2.1 and MCP profile defaults.
func validateRegistrationRequest(req *ClientRegistrationRequest, anonymous bool) error {
	// Without an explicit grant list the default is authorization_code plus refresh_token, so
	// redirect_uris is required.
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
		// Anonymous registration is capped by the spec section 9.10 policy.
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
		// Anonymous registration is public clients only (spec section 9.10).
		return wrapInvalidReg("anonymous clients must use token_endpoint_auth_method=none")
	}
	if req.ApplicationType == "" {
		req.ApplicationType = "web"
	}
	return nil
}

// validateRedirectURI enforces RFC 7591, RFC 8252 and OAuth 2.1 on a registered redirect URI: it
// must be absolute, carry no fragment or userinfo, and use https or a permitted loopback http form.
func validateRedirectURI(raw string) error {
	if err := cimd.ValidateRedirectURI(raw); err != nil {
		return wrapInvalidReg(err.Error())
	}
	return nil
}

// wrapInvalidReg wraps a validation message as the RFC 7591 invalid_client_metadata error.
func wrapInvalidReg(msg string) error {
	return &models.TheAuthError{Code: "invalid_client_metadata", Message: msg, Inner: models.ErrOAuthInvalidRequest}
}

// validateTokenMetadata rejects access token policy and RAR settings from anonymous registrants.
// Those settings control server-side behavior that only a trusted registrant should choose.
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
