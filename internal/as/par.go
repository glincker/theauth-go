package as

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// par.go implements RFC 9126 pushed authorization requests. POST /oauth/par validates the request,
// stores it behind a 256-bit request_uri and returns it. GET /oauth/authorize then accepts
// request_uri instead of inline parameters.

// PARConfig configures PAR. Non-nil presence on Config.PAR enables it; use DefaultPARConfig for a
// starting value.
type PARConfig struct {
	// RequestURITTL is how long a pushed request_uri stays valid (default 60 seconds, RFC 9126 section 2.2).
	RequestURITTL time.Duration

	// RequirePAR makes /oauth/authorize reject inline authorization parameters, so every request goes
	// through /oauth/par. Off by default.
	RequirePAR bool
}

// DefaultPARConfig returns a PARConfig with RFC 9126 recommended defaults.
func DefaultPARConfig() *PARConfig {
	return &PARConfig{RequestURITTL: 60 * time.Second}
}

func applyPARDefaults(c *PARConfig) {
	if c.RequestURITTL <= 0 {
		c.RequestURITTL = 60 * time.Second
	}
}

const requestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// PARStorage is the optional persistence for pushed requests. PAR is enabled only when the Storage
// implements it.
type PARStorage interface {
	// InsertPushedRequest persists a pushed request. payload is the JSON-serialized AuthorizeRequest
	// and expiresAt the absolute expiry.
	InsertPushedRequest(ctx context.Context, requestURI string, payload []byte, expiresAt time.Time) error

	// ConsumePushedRequest atomically fetches and deletes a pushed request. Missing, consumed and
	// expired requests all return ErrStorageNotFound, so callers cannot tell them apart by timing (RFC
	// 9126 section 4.3).
	ConsumePushedRequest(ctx context.Context, requestURI string) (payload []byte, err error)
}

// PARResponse is the JSON body returned by POST /oauth/par.
type PARResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// PushAuthorize validates the request, stores it and returns a request_uri. The caller
// authenticates the client first.
func (s *Service) PushAuthorize(ctx context.Context, req AuthorizeRequest) (PARResponse, error) {
	if s == nil {
		return PARResponse{}, errors.New("theauth: authorization server not configured")
	}
	if s.Cfg.PAR == nil {
		return PARResponse{}, models.ErrOAuthInvalidRequest
	}
	store, ok := s.Storage.(PARStorage)
	if !ok {
		return PARResponse{}, models.ErrOAuthInvalidRequest
	}

	if req.ResponseType != models.ResponseTypeCode {
		return PARResponse{}, models.ErrOAuthUnsupportedResponseType
	}
	if req.ClientID == "" {
		return PARResponse{}, models.ErrOAuthInvalidRequest
	}
	if req.CodeChallenge == "" || req.CodeChallengeMethod != "S256" {
		return PARResponse{}, models.ErrOAuthInvalidRequest
	}
	resource, audience, err := s.resolveResource(req.Resource)
	if err != nil {
		return PARResponse{}, err
	}
	client, err := s.ResolveClient(ctx, req.ClientID)
	if err != nil {
		return PARResponse{}, models.ErrOAuthInvalidClient
	}
	if !s.redirectURIRegistered(client.RedirectURIs, req.RedirectURI) {
		return PARResponse{}, models.ErrOAuthInvalidRequest
	}
	scope, err := s.narrowScopes(req.Scope, resource, client)
	if err != nil {
		return PARResponse{}, err
	}
	// Store the normalised values, so the later authorize call sees the canonical audience and the
	// narrowed scope.
	req.Resource = audience
	req.Scope = scope

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return PARResponse{}, err
	}
	requestURI := requestURIPrefix + hex.EncodeToString(token)

	payload, err := serializeAuthorizeRequest(req)
	if err != nil {
		return PARResponse{}, err
	}

	ttl := s.Cfg.PAR.RequestURITTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	expiresAt := time.Now().Add(ttl)
	if err := store.InsertPushedRequest(ctx, requestURI, payload, expiresAt); err != nil {
		return PARResponse{}, err
	}
	return PARResponse{
		RequestURI: requestURI,
		ExpiresIn:  int(ttl.Seconds()),
	}, nil
}

// ConsumePushedRequest looks up and atomically deletes a stored request, returning it or an error
// when missing or expired.
func (s *Service) ConsumePushedRequest(ctx context.Context, requestURI string) (AuthorizeRequest, error) {
	if s == nil {
		return AuthorizeRequest{}, errors.New("theauth: authorization server not configured")
	}
	store, ok := s.Storage.(PARStorage)
	if !ok {
		return AuthorizeRequest{}, models.ErrOAuthInvalidRequest
	}
	if !strings.HasPrefix(requestURI, requestURIPrefix) {
		return AuthorizeRequest{}, models.ErrOAuthInvalidRequest
	}
	payload, err := store.ConsumePushedRequest(ctx, requestURI)
	if err != nil {
		return AuthorizeRequest{}, models.ErrOAuthInvalidRequest
	}
	return deserializeAuthorizeRequest(payload)
}

// IsPAREnabled reports whether PAR is configured and the storage supports it.
func (s *Service) IsPAREnabled() bool {
	if s == nil || s.Cfg.PAR == nil {
		return false
	}
	_, ok := s.Storage.(PARStorage)
	return ok
}
