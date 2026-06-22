// SCIM token service. Extracted from root service_scim.go in PR A of the
// 2026-06 architecture reorg.
//
// Tokens are 256-bit base64url-encoded random strings; the sha256 hash is
// persisted and the plaintext is returned to the caller exactly once. The
// authenticator path (used by the SCIM bearer middleware) returns the
// bound organization or models.ErrInvalidToken and touches last_used_at on
// success.
//
// Perf re-audit 2026-06-21: AuthenticateResult bundles orgID + tokenID from
// a single storage round-trip, removing the double SCIMTokenByHash call the
// middleware previously performed. TouchSCIMTokenLastUsed is dispatched on a
// background goroutine so the auth hot path is never stalled by a write.
package scim

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
)

// Storage is the minimal persistence subset this package needs. Declared
// here (not imported from root) so the constructor cycle stays broken.
type Storage interface {
	InsertSCIMToken(ctx context.Context, t models.SCIMToken) (models.SCIMToken, error)
	SCIMTokenByHash(ctx context.Context, hash []byte) (*models.SCIMToken, error)
	SCIMTokensByOrg(ctx context.Context, orgID models.ULID) ([]models.SCIMToken, error)
	RevokeSCIMTokenByID(ctx context.Context, id models.ULID, at time.Time) error
	TouchSCIMTokenLastUsed(ctx context.Context, id models.ULID, at time.Time) error
}

// Config tracks the operator-supplied tunables (currently MaxPageSize and
// RequireHTTPS, neither of which the token methods need). Presence of a
// non-nil pointer is the enabled signal; nil disables CreateToken with
// ErrSCIMDisabled.
type Config struct {
	RequireHTTPS bool
	MaxPageSize  int
}

// ErrSCIMDisabled is returned by Service methods invoked when the root
// configuration did not enable SCIM. The root forwarder turns this into
// the legacy "theauth: SCIM not enabled" error string for backward compat.
var ErrSCIMDisabled = errors.New("scim: not enabled")

// Service holds the dependencies needed to mint, list, revoke, and
// authenticate SCIM bearer tokens.
type Service struct {
	storage Storage
	cfg     *Config
}

// NewService constructs a SCIM token Service. cfg may be nil; in that case
// CreateToken returns ErrSCIMDisabled (matching the legacy root behavior).
// The function is named NewService rather than New so it does not collide
// with the existing package-level filter helpers (ParseEqFilter et al).
func NewService(storage Storage, cfg *Config) *Service {
	return &Service{storage: storage, cfg: cfg}
}

// CreateToken mints a fresh 256-bit token, stores its sha256 hash, and
// returns the plaintext to the caller. The plaintext is the only point at
// which it leaves the library; subsequent reads only ever see the hash.
func (s *Service) CreateToken(ctx context.Context, orgID models.ULID, name string) (string, models.SCIMToken, error) {
	if s.cfg == nil {
		return "", models.SCIMToken{}, ErrSCIMDisabled
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", models.SCIMToken{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	rec := models.SCIMToken{
		ID:             ulid.New(),
		OrganizationID: orgID,
		Name:           name,
		TokenHash:      hash[:],
		CreatedAt:      time.Now(),
	}
	saved, err := s.storage.InsertSCIMToken(ctx, rec)
	if err != nil {
		return "", models.SCIMToken{}, err
	}
	return token, saved, nil
}

// RevokeToken marks the named token as revoked. Revoked tokens still
// resolve via SCIMTokenByHash but the middleware refuses them.
func (s *Service) RevokeToken(ctx context.Context, id models.ULID) error {
	return s.storage.RevokeSCIMTokenByID(ctx, id, time.Now())
}

// ListTokens returns every token (revoked or not) for the supplied org.
func (s *Service) ListTokens(ctx context.Context, orgID models.ULID) ([]models.SCIMToken, error) {
	return s.storage.SCIMTokensByOrg(ctx, orgID)
}

// AuthenticateResult bundles the organization ID and token row ID returned
// by a single Authenticate call. The middleware stashes TokenID on the
// request context for audit emission, removing the second SCIMTokenByHash
// lookup that the old TokenIDByPresented path required.
type AuthenticateResult struct {
	OrganizationID models.ULID
	TokenID        models.ULID
}

// Authenticate is the entry point invoked by the SCIM bearer middleware
// on every request. Returns the bound organization and token row ID in a
// single storage round-trip, or models.ErrInvalidToken on failure.
// TouchSCIMTokenLastUsed is dispatched asynchronously so the auth hot
// path never blocks on a write (perf re-audit 2026-06-21, item 1).
func (s *Service) Authenticate(ctx context.Context, presented string) (AuthenticateResult, error) {
	if presented == "" {
		return AuthenticateResult{}, models.ErrInvalidToken
	}
	hash := sha256.Sum256([]byte(presented))
	rec, err := s.storage.SCIMTokenByHash(ctx, hash[:])
	if err != nil {
		if errors.Is(err, models.ErrStorageNotFound) {
			return AuthenticateResult{}, models.ErrInvalidToken
		}
		return AuthenticateResult{}, err
	}
	if rec.RevokedAt != nil {
		return AuthenticateResult{}, models.ErrInvalidToken
	}
	// Fire-and-forget: dispatch the last_used_at update asynchronously so
	// the SCIM request is never stalled by the write. Drop on full channel
	// is acceptable (the field is informational, not security-critical).
	go func() {
		_ = s.storage.TouchSCIMTokenLastUsed(context.Background(), rec.ID, time.Now())
	}()
	return AuthenticateResult{
		OrganizationID: rec.OrganizationID,
		TokenID:        rec.ID,
	}, nil
}
