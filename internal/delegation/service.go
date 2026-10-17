// Package delegation owns the delegation grant lifecycle: grant, list, revoke, and the Active and
// NarrowScope helpers the AS uses for token exchange and introspection, so those helpers live in
// one place. It is a leaf package. Callers gate the user_id parameter themselves; the service does
// not enforce authorization.
package delegation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/chain"
	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// Storage is the minimal persistence subset this package needs. It is declared here to keep the
// constructor cycle broken.
type Storage interface {
	AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error)
	InsertDelegationGrant(ctx context.Context, g models.DelegationGrant) (models.DelegationGrant, error)
	DelegationGrantByID(ctx context.Context, id models.ULID) (*models.DelegationGrant, error)
	DelegationGrantsByUserID(ctx context.Context, userID models.ULID) ([]models.DelegationGrant, error)
	DelegationGrantsByAgentID(ctx context.Context, agentID models.ULID) ([]models.DelegationGrant, error)
	RevokeDelegationGrant(ctx context.Context, id models.ULID, at time.Time, reason string) error
}

// ResourceLookup resolves a protected-resource identifier to its configured ProtectedResource. The
// AS satisfies it.
type ResourceLookup interface {
	ResourceByIdentifier(id string) (models.ProtectedResource, bool)
}

// Config is the subset of AgentConfig that gates delegation issuance.
type Config struct {
	// MaxDelegationDuration caps any single delegation_grants.max_duration.
	MaxDelegationDuration time.Duration
}

// Service holds the delegation dependencies. Root constructs it and reaches it through thin forwarders.
type Service struct {
	storage  Storage
	cfg      *Config
	resource ResourceLookup
	auditEm  audit.Emitter
	hooks    *obs.Hooks
}

// New constructs a delegation Service. A nil cfg makes every method return the "agent identity not
// configured" sentinel. A nil emitter becomes audit.NoopEmitter.
func New(storage Storage, cfg *Config, resource ResourceLookup, em audit.Emitter) *Service {
	if em == nil {
		em = audit.NoopEmitter{}
	}
	return &Service{storage: storage, cfg: cfg, resource: resource, auditEm: em, hooks: &obs.Hooks{}}
}

// ready reports whether the service has the pieces every public method needs.
func (s *Service) ready() bool {
	return s != nil && s.cfg != nil && s.storage != nil
}

// tracer returns the hooks bundle, or an empty one when unset, so a Service
// built as a literal never dereferences nil.
func (s *Service) tracer() *obs.Hooks {
	if s.hooks == nil {
		return &obs.Hooks{}
	}
	return s.hooks
}

// emit forwards to the audit emitter, tolerating an unset one.
func (s *Service) emit(ctx context.Context, action string, target models.TargetRef, md map[string]any) {
	if s.auditEm == nil {
		return
	}
	s.auditEm.EmitAudit(ctx, action, target, md)
}

// SetHooks installs the observability bundle. It is idempotent.
func (s *Service) SetHooks(h *obs.Hooks) {
	if s == nil {
		return
	}
	if h == nil {
		h = &obs.Hooks{}
	}
	s.hooks = h
}

// errNotConfigured is the legacy "agent identity not configured" sentinel. It is wrapped so string
// comparisons keep working.
var errNotConfigured = errors.New("theauth: agent identity not configured")

// GrantDelegation persists a delegation grant. Scope must be a subset of the ProtectedResource
// scopes, resource must be a known identifier, and max_duration_seconds must be in (0,
// MaxDelegationDuration].
func (s *Service) GrantDelegation(ctx context.Context, in models.GrantDelegationInput) (grant models.DelegationGrant, err error) {
	if !s.ready() {
		return models.DelegationGrant{}, errNotConfigured
	}
	if s.resource == nil {
		return models.DelegationGrant{}, errNotConfigured
	}
	ctx, span := s.tracer().StartSpan(ctx, obs.SpanDelegationGrant)
	defer func() {
		status := obs.StatusSuccess
		if err != nil {
			status = obs.StatusError
			span.RecordError(err)
		}
		span.SetAttributes(obs.StringAttr(obs.AttrStatus, string(status)))
		span.End()
	}()
	if in.Resource == "" {
		return models.DelegationGrant{}, models.ErrOAuthInvalidResource
	}
	resource, ok := s.resource.ResourceByIdentifier(in.Resource)
	if !ok {
		return models.DelegationGrant{}, models.ErrOAuthInvalidResource
	}
	if len(in.Scope) == 0 {
		return models.DelegationGrant{}, models.ErrOAuthInvalidScope
	}
	if _, err := validateScopeAgainstResource(in.Scope, resource); err != nil {
		return models.DelegationGrant{}, err
	}
	if in.MaxDurationSeconds <= 0 {
		return models.DelegationGrant{}, errors.New("theauth: GrantDelegation MaxDurationSeconds must be > 0")
	}
	maxSeconds := int(s.cfg.MaxDelegationDuration.Seconds())
	if in.MaxDurationSeconds > maxSeconds {
		return models.DelegationGrant{}, fmt.Errorf("theauth: MaxDurationSeconds exceeds policy cap %d", maxSeconds)
	}
	// Verify the agent exists and is active before we record any approval.
	ag, err := s.storage.AgentByID(ctx, in.AgentID)
	if err != nil {
		return models.DelegationGrant{}, models.ErrAgentNotFound
	}
	if ag.Status != models.AgentStatusActive {
		return models.DelegationGrant{}, models.ErrAgentInactive
	}
	now := time.Now().UTC()
	row := models.DelegationGrant{
		ID:                 ulid.New(),
		UserID:             in.UserID,
		AgentID:            in.AgentID,
		OrganizationID:     in.OrganizationID,
		Scope:              append([]string(nil), in.Scope...),
		Resource:           in.Resource,
		MaxDurationSeconds: in.MaxDurationSeconds,
		CreatedAt:          now,
		ExpiresAt:          in.ExpiresAt,
	}
	stored, err := s.storage.InsertDelegationGrant(ctx, row)
	if err != nil {
		return models.DelegationGrant{}, fmt.Errorf("persist delegation grant: %w", err)
	}
	s.emit(ctx, "delegation.granted", models.TargetRef{Type: "delegation_grant", ID: stored.ID.String()}, map[string]any{
		"grant_id":             stored.ID.String(),
		"user_id":              stored.UserID.String(),
		"agent_id":             stored.AgentID.String(),
		"resource":             stored.Resource,
		"scope":                stored.Scope,
		"max_duration_seconds": stored.MaxDurationSeconds,
	})
	return stored, nil
}

// ListDelegationsForUser returns every grant the user has issued, including
// revoked ones (for audit / display). Callers can filter on RevokedAt.
func (s *Service) ListDelegationsForUser(ctx context.Context, userID models.ULID) ([]models.DelegationGrant, error) {
	if !s.ready() {
		return nil, errNotConfigured
	}
	return s.storage.DelegationGrantsByUserID(ctx, userID)
}

// ListDelegationsForAgent returns every grant naming the supplied agent.
func (s *Service) ListDelegationsForAgent(ctx context.Context, agentID models.ULID) ([]models.DelegationGrant, error) {
	if !s.ready() {
		return nil, errNotConfigured
	}
	return s.storage.DelegationGrantsByAgentID(ctx, agentID)
}

// RevokeDelegation revokes a grant. Tokens minted under it fail at the next introspection refresh,
// within IntrospectionCacheTTL.
func (s *Service) RevokeDelegation(ctx context.Context, grantID models.ULID, reason string) (err error) {
	if !s.ready() {
		return errNotConfigured
	}
	ctx, span := s.tracer().StartSpan(ctx, obs.SpanDelegationRevoke)
	defer func() {
		status := obs.StatusSuccess
		if err != nil {
			status = obs.StatusError
			span.RecordError(err)
		}
		span.SetAttributes(obs.StringAttr(obs.AttrStatus, string(status)))
		span.End()
	}()
	cur, lerr := s.storage.DelegationGrantByID(ctx, grantID)
	if lerr != nil {
		err = models.ErrDelegationNotFound
		return err
	}
	if cur.RevokedAt != nil {
		// Idempotent: a second revoke is a no-op.
		return nil
	}
	now := time.Now().UTC()
	// The revoke is conditional on revoked_at being null. A lost race is treated as success, so
	// exactly one revoked event is emitted.
	if err := s.storage.RevokeDelegationGrant(ctx, grantID, now, reason); err != nil {
		if errors.Is(err, models.ErrStorageNotFound) {
			if again, gerr := s.storage.DelegationGrantByID(ctx, grantID); gerr == nil && again.RevokedAt != nil {
				return nil
			}
		}
		return fmt.Errorf("revoke delegation: %w", err)
	}
	s.emit(ctx, "delegation.revoked", models.TargetRef{Type: "delegation_grant", ID: grantID.String()}, map[string]any{
		"grant_id": grantID.String(),
		"user_id":  cur.UserID.String(),
		"agent_id": cur.AgentID.String(),
		"resource": cur.Resource,
		"reason":   reason,
	})
	return nil
}

// GrantByID returns the persisted grant, for ownership checks in handler code. The storage error is
// returned unwrapped.
func (s *Service) GrantByID(ctx context.Context, grantID models.ULID) (*models.DelegationGrant, error) {
	if s == nil || s.storage == nil {
		return nil, errNotConfigured
	}
	return s.storage.DelegationGrantByID(ctx, grantID)
}

// Active reports whether the supplied grant is currently usable for token
// exchange: not revoked and not past its expires_at envelope (if set).
// Token exchange + introspection both call this on every check to keep
// cascade revocation observable inside IntrospectionCacheTTL. Canonical
// single definition; internal/as imports this package rather than carry a
// duplicate.
func Active(g *models.DelegationGrant, now time.Time) bool {
	if g == nil || g.RevokedAt != nil {
		return false
	}
	if g.ExpiresAt != nil && !now.Before(*g.ExpiresAt) {
		return false
	}
	return true
}

// NarrowScope returns the strict intersection of (requested, subject_scope,
// grant_scope). Empty result means the caller asked for nothing the chain
// still allows; the token-exchange path treats that as invalid_scope.
// Canonical single definition; internal/as imports this package rather
// than carry a duplicate.
func NarrowScope(requested, subjectScope, grantScope []string) ([]string, bool) {
	if len(requested) == 0 {
		// Default to the strict intersection of subject and grant; falls
		// back to the grant scope when subject scope is empty.
		base := subjectScope
		if len(base) == 0 {
			base = grantScope
		}
		return chain.ScopeIntersect(base, grantScope), true
	}
	if !chain.ScopeSubset(requested, subjectScope) {
		return nil, false
	}
	if !chain.ScopeSubset(requested, grantScope) {
		return nil, false
	}
	return append([]string(nil), requested...), true
}

// validateScopeAgainstResource returns the intersection of requested and
// supported scopes; returns error if requested contains any scope outside
// the resource's catalog. Mirror of the root scope_helpers.go and the
// internal/as helper (the AS copy stays because it is called from
// non-delegation code paths).
func validateScopeAgainstResource(requested []string, resource models.ProtectedResource) ([]string, error) {
	if len(requested) == 0 {
		return nil, errors.New("scope required")
	}
	if len(resource.Scopes) == 0 {
		return requested, nil
	}
	supported := map[string]struct{}{}
	for _, sc := range resource.Scopes {
		supported[sc] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	for _, sc := range requested {
		if _, ok := supported[sc]; !ok {
			return nil, models.ErrOAuthInvalidScope
		}
		out = append(out, sc)
	}
	return out, nil
}
