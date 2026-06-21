package theauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
)

// service_dcr.go: RFC 7591 dynamic client registration.
//
// Two modes:
//   bearer-gated (default): the caller MUST present a non-empty Bearer token
//     on POST /oauth/register. Phase 1 + 2 treats this as any non-empty token
//     so operators can issue initial access tokens out-of-band; a richer
//     validation surface (per-issuer token introspection) lands in phase 3.
//   anonymous: enabled via Config.AuthorizationServer.AllowAnonymousRegistration.
//     Public MCP servers need this; the handler hard-pins the endpoint to
//     1 request/min/IP and stamps anonymous_registered = true on the resulting
//     OAuthClient row for operator auditing.

// ClientRegistrationRequest is the parsed JSON body of POST /oauth/register.
// Field names match RFC 7591 client metadata exactly so the wire form maps
// 1:1 onto the struct.
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

// RegisteredClient is the JSON body returned on a successful registration
// (RFC 7591 section 3.2.1). The client_secret is returned in plaintext
// exactly once; the AS stores only the Argon2id hash.
type RegisteredClient struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type"`
	ClientName              string   `json:"client_name,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	JwksURI                 string   `json:"jwks_uri,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

// RegisterClient validates the request, mints a client_id (and a secret for
// confidential clients), persists the OAuthClient row, and returns the
// RFC 7591 response body. The plaintext secret is in the return value;
// callers must surface it to the caller exactly once and never log it.
func (a *TheAuth) RegisterClient(ctx context.Context, req ClientRegistrationRequest, anonymous bool) (RegisteredClient, error) {
	if a.as == nil {
		return RegisteredClient{}, errors.New("theauth: authorization server not configured")
	}
	if anonymous && !a.as.cfg.AllowAnonymousRegistration {
		return RegisteredClient{}, ErrOAuthRegistrationDenied
	}
	if err := validateRegistrationRequest(&req, anonymous); err != nil {
		return RegisteredClient{}, err
	}
	clientID := "client-" + ulid.New().String()
	now := time.Now().UTC()
	client := OAuthClient{
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
	resp := RegisteredClient{
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
	if req.TokenEndpointAuthMethod != ClientAuthNone {
		secret, err := crypto.NewToken()
		if err != nil {
			return RegisteredClient{}, fmt.Errorf("generate client secret: %w", err)
		}
		hash, err := crypto.HashPassword(secret)
		if err != nil {
			return RegisteredClient{}, fmt.Errorf("hash client secret: %w", err)
		}
		client.ClientSecretHash = []byte(hash)
		resp.ClientSecret = secret
		// Anonymous clients get a 30-day secret TTL; bearer-gated clients
		// effectively never expire (0 per RFC 7591 means "never").
		if anonymous {
			resp.ClientSecretExpiresAt = now.Add(30 * 24 * time.Hour).Unix()
		}
	}
	stored, err := a.as.storage.InsertOAuthClient(ctx, client)
	if err != nil {
		return RegisteredClient{}, fmt.Errorf("persist oauth client: %w", err)
	}
	resp.ClientID = stored.ClientID
	return resp, nil
}

// validateRegistrationRequest screens RFC 7591 metadata and applies defaults
// matching the OAuth 2.1 + MCP profile.
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
		req.GrantTypes = []string{GrantTypeAuthorizationCode, GrantTypeRefreshToken}
	}
	for _, gt := range req.GrantTypes {
		switch gt {
		case GrantTypeAuthorizationCode, GrantTypeRefreshToken:
			// supported
		default:
			return wrapInvalidReg("unsupported grant_type: " + gt)
		}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{ResponseTypeCode}
	}
	for _, rt := range req.ResponseTypes {
		if rt != ResponseTypeCode {
			return wrapInvalidReg("unsupported response_type: " + rt)
		}
	}
	if req.TokenEndpointAuthMethod == "" {
		if anonymous {
			req.TokenEndpointAuthMethod = ClientAuthNone
		} else {
			req.TokenEndpointAuthMethod = ClientAuthSecretBasic
		}
	}
	switch req.TokenEndpointAuthMethod {
	case ClientAuthSecretBasic, ClientAuthSecretPost, ClientAuthNone:
	default:
		return wrapInvalidReg("unsupported token_endpoint_auth_method: " + req.TokenEndpointAuthMethod)
	}
	if anonymous && req.TokenEndpointAuthMethod != ClientAuthNone {
		// Public clients only for anonymous registration; spec section 9.10.
		return wrapInvalidReg("anonymous clients must use token_endpoint_auth_method=none")
	}
	if req.ApplicationType == "" {
		req.ApplicationType = "web"
	}
	return nil
}

// validateRedirectURI enforces RFC 7591 + OAuth 2.1: URI MUST parse, MUST
// have an absolute scheme, MUST NOT contain a fragment. Web app schemes are
// limited to https and localhost http for development; native app schemes
// (custom or loopback) are permitted but not exhaustively whitelisted.
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
	return &TheAuthError{Code: "invalid_client_metadata", Message: msg, Inner: ErrOAuthInvalidRequest}
}
