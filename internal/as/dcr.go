package as

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
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
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

// RegisterClient validates the request, mints a client_id (and a secret
// for confidential clients), persists the OAuthClient row, and returns
// the RFC 7591 response body. The plaintext secret is in the return
// value; callers must surface it to the caller exactly once and never
// log it.
func (s *Service) RegisterClient(ctx context.Context, req ClientRegistrationRequest, anonymous bool) (models.RegisteredClient, error) {
	if s == nil {
		return models.RegisteredClient{}, errors.New("theauth: authorization server not configured")
	}
	if anonymous && !s.Cfg.AllowAnonymousRegistration {
		return models.RegisteredClient{}, models.ErrOAuthRegistrationDenied
	}
	if err := validateRegistrationRequest(&req, anonymous); err != nil {
		return models.RegisteredClient{}, err
	}
	clientID := "client-" + ulid.New().String()
	now := time.Now().UTC()
	client := models.OAuthClient{
		ID:                      ulid.New(),
		ClientID:                clientID,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		Scope:                   req.Scope,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		ApplicationType:         req.ApplicationType,
		Contacts:                req.Contacts,
		LogoURI:                 req.LogoURI,
		PolicyURI:               req.PolicyURI,
		TosURI:                  req.TosURI,
		JwksURI:                 req.JwksURI,
		SoftwareID:              req.SoftwareID,
		SoftwareVersion:         req.SoftwareVersion,
		AnonymousRegistered:     anonymous,
		CreatedAt:               now,
		UpdatedAt:               now,
	}
	resp := models.RegisteredClient{
		ClientID:                clientID,
		ClientIDIssuedAt:        now.Unix(),
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		Scope:                   req.Scope,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		ApplicationType:         req.ApplicationType,
		ClientName:              req.ClientName,
		Contacts:                req.Contacts,
		LogoURI:                 req.LogoURI,
		PolicyURI:               req.PolicyURI,
		TosURI:                  req.TosURI,
		JwksURI:                 req.JwksURI,
		SoftwareID:              req.SoftwareID,
		SoftwareVersion:         req.SoftwareVersion,
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
	if len(req.RedirectURIs) == 0 {
		return wrapInvalidReg("redirect_uris is required")
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
		case models.GrantTypeAuthorizationCode, models.GrantTypeRefreshToken:
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

// validateRedirectURI enforces RFC 7591 + OAuth 2.1: URI MUST parse,
// MUST have an absolute scheme, MUST NOT contain a fragment. Web app
// schemes are limited to https and localhost http for development;
// native app schemes (custom or loopback) are permitted but not
// exhaustively whitelisted.
func validateRedirectURI(raw string) error {
	if raw == "" {
		return wrapInvalidReg("empty redirect_uri")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return wrapInvalidReg("redirect_uri parse failed: " + err.Error())
	}
	if u.Scheme == "" {
		return wrapInvalidReg("redirect_uri must be absolute")
	}
	if u.Fragment != "" {
		return wrapInvalidReg("redirect_uri must not contain a fragment")
	}
	if u.Scheme == "http" {
		host := strings.ToLower(u.Hostname())
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return wrapInvalidReg("http redirect_uri is only allowed for localhost")
		}
	}
	return nil
}

// wrapInvalidReg wraps an arbitrary validation message as the RFC 7591
// invalid_client_metadata error code. Handlers map this to 400 with
// {error: "invalid_client_metadata", error_description: <message>}.
func wrapInvalidReg(msg string) error {
	return &models.TheAuthError{Code: "invalid_client_metadata", Message: msg, Inner: models.ErrOAuthInvalidRequest}
}
