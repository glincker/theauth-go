package as

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go/internal/models"
)

// par.go: RFC 9126 Pushed Authorization Requests (PAR).
//
// POST /oauth/par accepts the same parameters as /oauth/authorize, validates
// them immediately, stores the payload behind a request_uri of the form
// urn:ietf:params:oauth:request_uri:<256-bit-random>, and returns:
//
//	{"request_uri": "...", "expires_in": <seconds>}
//
// GET /oauth/authorize then accepts request_uri instead of (or in addition
// to, which is an error) inline parameters.

// PARConfig holds the knobs for the PAR sub-system. Non-nil presence
// on Config.PAR enables PAR. The zero value is not valid; use
// DefaultPARConfig() when constructing a custom value.
type PARConfig struct {
	// RequestURITTL is how long a pushed request_uri stays valid.
	// Defaults to 60 seconds per RFC 9126 section 2.2.
	RequestURITTL time.Duration

	// RequirePAR, when true, causes /oauth/authorize to reject any request
	// that carries inline authorization parameters (i.e. every request must
	// first go through /oauth/par). Off by default.
	RequirePAR bool
}

// DefaultPARConfig returns a PARConfig with RFC 9126 recommended defaults.
func DefaultPARConfig() *PARConfig {
	return &PARConfig{RequestURITTL: 60 * time.Second}
}

// applyPARDefaults fills in zero-value PARConfig fields.
func applyPARDefaults(c *PARConfig) {
	if c.RequestURITTL <= 0 {
		c.RequestURITTL = 60 * time.Second
	}
}

// requestURIPrefix is the URN prefix mandated by RFC 9126 section 2.2.
const requestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// PARStorage is the optional persistence interface for pushed authorization
// requests. When the Storage passed to as.New also satisfies PARStorage, PAR
// is enabled. When the backend does not implement it, PAR is automatically
// disabled (even if Config.PAR is set).
type PARStorage interface {
	// InsertPushedRequest persists a pushed request. requestURI is the full
	// urn:ietf:params:oauth:request_uri:<token> string. payload is the
	// JSON-serialized AuthorizeRequest. expiresAt is the absolute expiry.
	InsertPushedRequest(ctx context.Context, requestURI string, payload []byte, expiresAt time.Time) error

	// ConsumePushedRequest atomically fetches and deletes the pushed request
	// identified by requestURI. Returns ErrStorageNotFound when the URI has
	// already been consumed, never existed, or is expired. Callers MUST
	// treat not-found and expired identically to prevent timing side channels
	// (RFC 9126 section 4.3).
	ConsumePushedRequest(ctx context.Context, requestURI string) (payload []byte, err error)
}

// PARResponse is the JSON body returned by POST /oauth/par.
type PARResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// PushAuthorize validates the request, stores it, and returns a request_uri.
// The caller is responsible for client authentication before invoking this.
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

	// Validate parameters the same way /oauth/authorize does.
	if req.ResponseType != models.ResponseTypeCode {
		return PARResponse{}, models.ErrOAuthUnsupportedResponseType
	}
	if req.ClientID == "" {
		return PARResponse{}, models.ErrOAuthInvalidRequest
	}
	if req.CodeChallenge == "" || req.CodeChallengeMethod != "S256" {
		return PARResponse{}, models.ErrOAuthInvalidRequest
	}
	if req.Resource == "" {
		return PARResponse{}, models.ErrOAuthInvalidResource
	}
	if _, ok := s.ResourceByIdentifier(req.Resource); !ok {
		return PARResponse{}, models.ErrOAuthInvalidResource
	}
	client, err := s.ResolveClient(ctx, req.ClientID)
	if err != nil {
		return PARResponse{}, models.ErrOAuthInvalidClient
	}
	if !redirectURIRegistered(client.RedirectURIs, req.RedirectURI) {
		return PARResponse{}, models.ErrOAuthInvalidRequest
	}
	if _, err := validateScopeAgainstResource(req.Scope, models.ProtectedResource{}); err != nil {
		// If resource scopes are empty that is fine; do full validation.
		resource, _ := s.ResourceByIdentifier(req.Resource)
		if _, e2 := validateScopeAgainstResource(req.Scope, resource); e2 != nil {
			return PARResponse{}, e2
		}
	}

	// Mint request_uri.
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return PARResponse{}, err
	}
	requestURI := requestURIPrefix + hex.EncodeToString(token)

	// Serialize the validated request for storage.
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

// ConsumePushedRequest looks up and atomically deletes the stored request.
// Returns the deserialized AuthorizeRequest or an error if not found/expired.
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

// IsPAREnabled reports whether PAR is configured and the storage backend
// supports it.
func (s *Service) IsPAREnabled() bool {
	if s == nil || s.Cfg.PAR == nil {
		return false
	}
	_, ok := s.Storage.(PARStorage)
	return ok
}
