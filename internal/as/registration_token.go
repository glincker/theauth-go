package as

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// registration_token.go: initial access tokens for POST /oauth/register
// (RFC 7591 section 1.2), used to register agents and other clients without
// opening anonymous registration.
//
// A token is created by an admin, shown once, stored only as a SHA-256
// digest, limited to MaxUses redemptions (default 1), expires, and can cap the
// scopes and grant types of the client it registers. Every lifecycle step
// emits an audit event.

const (
	registrationTokenPrefix = "rt_"
	// maxRegistrationTokenUses bounds MaxUses so a typo cannot mint a
	// practically unlimited token.
	maxRegistrationTokenUses = 1000
)

// CreateRegistrationTokenInput describes a token to mint.
type CreateRegistrationTokenInput struct {
	Label          string
	OrganizationID *models.ULID
	// Scopes and GrantTypes cap what the registered client may declare.
	// Empty means unrestricted.
	Scopes     []string
	GrantTypes []string
	// MaxUses defaults to 1 (one-time).
	MaxUses int
	// TTL defaults to Config.RegistrationTokenTTL.
	TTL       time.Duration
	CreatedBy *models.ULID
}

func (s *Service) registrationStore() (RegistrationTokenStorage, bool) {
	if s == nil {
		return nil, false
	}
	st, ok := s.Storage.(RegistrationTokenStorage)
	return st, ok
}

// RegistrationTokensEnabled reports whether the storage supports stored
// registration tokens.
func (s *Service) RegistrationTokensEnabled() bool {
	_, ok := s.registrationStore()
	return ok
}

// CreateRegistrationToken mints a token and returns the stored record plus the
// plaintext, which is not recoverable afterwards.
func (s *Service) CreateRegistrationToken(ctx context.Context, in CreateRegistrationTokenInput) (models.RegistrationToken, string, error) {
	store, ok := s.registrationStore()
	if !ok {
		return models.RegistrationToken{}, "", models.ErrRegistrationTokensDisabled
	}
	if in.MaxUses == 0 {
		in.MaxUses = 1
	}
	if in.MaxUses < 0 || in.MaxUses > maxRegistrationTokenUses {
		return models.RegistrationToken{}, "", models.ErrOAuthInvalidRequest
	}
	if in.TTL == 0 {
		in.TTL = s.Cfg.RegistrationTokenTTL
	}
	if in.TTL < 0 {
		return models.RegistrationToken{}, "", models.ErrOAuthInvalidRequest
	}
	for _, g := range in.GrantTypes {
		if !registrationGrantAllowed(g) {
			return models.RegistrationToken{}, "", models.ErrOAuthInvalidRequest
		}
	}
	secret, err := crypto.NewToken()
	if err != nil {
		return models.RegistrationToken{}, "", err
	}
	raw := registrationTokenPrefix + secret
	now := s.now().UTC()
	t := models.RegistrationToken{
		ID:             ulid.New(),
		TokenHash:      crypto.HashToken(raw),
		Prefix:         raw[:len(registrationTokenPrefix)+4],
		Label:          in.Label,
		OrganizationID: in.OrganizationID,
		Scopes:         append([]string(nil), in.Scopes...),
		GrantTypes:     append([]string(nil), in.GrantTypes...),
		MaxUses:        in.MaxUses,
		CreatedBy:      in.CreatedBy,
		CreatedAt:      now,
		ExpiresAt:      now.Add(in.TTL),
	}
	if err := store.InsertRegistrationToken(ctx, t); err != nil {
		return models.RegistrationToken{}, "", err
	}
	meta := map[string]any{"label": t.Label, "max_uses": t.MaxUses, "expires_at": t.ExpiresAt.Format(time.RFC3339)}
	if in.CreatedBy != nil {
		meta["created_by"] = in.CreatedBy.String()
	}
	s.Audit.EmitAudit(ctx, "oauth.registration_token.created",
		models.TargetRef{Type: "registration_token", ID: t.ID.String()}, meta)
	return t, raw, nil
}

func registrationGrantAllowed(g string) bool {
	switch g {
	case models.GrantTypeAuthorizationCode, models.GrantTypeRefreshToken,
		models.GrantTypeClientCredentials, models.GrantTypeTokenExchange,
		models.GrantTypeCIBA, models.GrantTypeDeviceCode:
		return true
	}
	return false
}

// ListRegistrationTokens lists tokens, newest first. A nil orgID lists all.
func (s *Service) ListRegistrationTokens(ctx context.Context, orgID *models.ULID) ([]models.RegistrationToken, error) {
	store, ok := s.registrationStore()
	if !ok {
		return nil, models.ErrRegistrationTokensDisabled
	}
	return store.ListRegistrationTokens(ctx, orgID)
}

// RevokeRegistrationToken revokes a token. When orgID is non-nil the token
// must belong to that organization, otherwise ErrStorageNotFound is returned
// so an admin cannot probe other organizations' token IDs.
func (s *Service) RevokeRegistrationToken(ctx context.Context, id models.ULID, orgID *models.ULID, actor *models.ULID) error {
	store, ok := s.registrationStore()
	if !ok {
		return models.ErrRegistrationTokensDisabled
	}
	t, err := store.RegistrationTokenByID(ctx, id)
	if err != nil {
		return err
	}
	if orgID != nil && (t.OrganizationID == nil || *t.OrganizationID != *orgID) {
		return models.ErrStorageNotFound
	}
	changed, err := store.RevokeRegistrationToken(ctx, id, s.now().UTC())
	if err != nil {
		return err
	}
	if changed {
		meta := map[string]any{"label": t.Label}
		if actor != nil {
			meta["revoked_by"] = actor.String()
		}
		s.Audit.EmitAudit(ctx, "oauth.registration_token.revoked",
			models.TargetRef{Type: "registration_token", ID: id.String()}, meta)
	}
	return nil
}

// RedeemRegistrationToken validates raw against the stored tokens and the
// registration request, then spends one use. The returned token must be passed
// to RefundRegistrationToken if the registration then fails.
//
// Unknown, expired, revoked and exhausted tokens all return
// ErrRegistrationTokenInvalid. A valid token whose scope does not cover the
// request returns ErrRegistrationTokenScope without spending a use.
func (s *Service) RedeemRegistrationToken(ctx context.Context, raw string, req ClientRegistrationRequest) (*models.RegistrationToken, error) {
	store, ok := s.registrationStore()
	if !ok || !strings.HasPrefix(raw, registrationTokenPrefix) {
		return nil, models.ErrRegistrationTokenInvalid
	}
	t, err := store.RegistrationTokenByHash(ctx, crypto.HashToken(raw))
	if err != nil {
		if errors.Is(err, models.ErrStorageNotFound) {
			return nil, models.ErrRegistrationTokenInvalid
		}
		return nil, err
	}
	now := s.now().UTC()
	if !t.Active(now) {
		return nil, models.ErrRegistrationTokenInvalid
	}
	if !registrationWithinScope(*t, req) {
		s.Audit.EmitAudit(ctx, "oauth.registration_token.rejected",
			models.TargetRef{Type: "registration_token", ID: t.ID.String()},
			map[string]any{"reason": "scope_exceeded"})
		return nil, models.ErrRegistrationTokenScope
	}
	spent, err := store.RedeemRegistrationToken(ctx, t.ID, now)
	if err != nil {
		return nil, err
	}
	if !spent {
		return nil, models.ErrRegistrationTokenInvalid
	}
	t.Uses++
	return t, nil
}

// RefundRegistrationToken gives back the use taken by RedeemRegistrationToken
// when the registration failed afterwards.
func (s *Service) RefundRegistrationToken(ctx context.Context, id models.ULID) {
	if store, ok := s.registrationStore(); ok {
		_ = store.RefundRegistrationToken(ctx, id)
	}
}

// RegistrationSucceeded emits the redemption audit event once the client
// exists.
func (s *Service) RegistrationSucceeded(ctx context.Context, t *models.RegistrationToken, clientID string) {
	s.Audit.EmitAudit(ctx, "oauth.registration_token.redeemed",
		models.TargetRef{Type: "registration_token", ID: t.ID.String()},
		map[string]any{"client_id": clientID, "uses": t.Uses, "max_uses": t.MaxUses})
}

func registrationWithinScope(t models.RegistrationToken, req ClientRegistrationRequest) bool {
	if len(t.Scopes) > 0 && !scopeSubset(scopeSplit(req.Scope), t.Scopes) {
		return false
	}
	if len(t.GrantTypes) > 0 {
		effective := req.GrantTypes
		if len(effective) == 0 {
			effective = []string{models.GrantTypeAuthorizationCode, models.GrantTypeRefreshToken}
		}
		if !scopeSubset(effective, t.GrantTypes) {
			return false
		}
	}
	return true
}
