// Package delegation owns the v2.0 delegation_grants lifecycle: GrantDelegation,
// ListDelegationsForUser, ListDelegationsForAgent, RevokeDelegation, and the
// canonical Active + NarrowScope helpers consulted by the AS token-exchange
// and introspection paths. Extracted from root service_delegation.go in PR C
// of the 2026-06 architecture reorg.
//
// The package is a leaf in the internal dependency graph: it imports
// internal/models, internal/audit, internal/chain, and internal/ulid only.
// internal/as imports this package for Active + NarrowScope so the helpers
// live in exactly one place; internal/agent imports this package indirectly
// through the audit emitter only.
//
// RBAC: callers MUST gate the user_id parameter on the authenticated user
// (or an organization admin acting in scope). The service surface itself
// does not enforce that gate; handler-layer code does.
package delegation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/chain"
	"github.com/glincker/theauth-go/internal/models"
	obs "github.com/glincker/theauth-go/internal/observability"
	"github.com/glincker/theauth-go/internal/ulid"
)

// Storage is the minimal persistence subset this package needs. Declared
// here (not imported from root) so internal/delegation does not import
// github.com/glincker/theauth-go, which would form an import cycle with the
// root constructor. Any type satisfying these methods (notably the root
// theauth.Storage when it also implements OAuthServerStorage) is a valid
// argument to New.
type Storage interface {
	AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error)
	InsertDelegationGrant(ctx context.Context, g models.DelegationGrant) (models.DelegationGrant, error)
	DelegationGrantByID(ctx context.Context, id models.ULID) (*models.DelegationGrant, error)
	DelegationGrantsByUserID(ctx context.Context, userID models.ULID) ([]models.DelegationGrant, error)
	DelegationGrantsByAgentID(ctx context.Context, agentID models.ULID) ([]models.DelegationGrant, error)
	RevokeDelegationGrant(ctx context.Context, id models.ULID, at time.Time, reason string) error
}

// ResourceLookup resolves a protected-resource identifier into the configured
// ProtectedResource. The AS service satisfies this naturally (it owns the
// catalog); we depend on the interface so internal/delegation does not import
// internal/as.
type ResourceLookup interface {
	ResourceByIdentifier(id string) (models.ProtectedResource, bool)
}

// Config bundles the validated agent-identity policy fields this package
// needs at grant time. Mirrors the subset of root AgentConfig that gates
// delegation issuance.
type Config struct {
	// MaxDelegationDuration caps any single delegation_grants.max_duration.
	MaxDelegationDuration time.Duration
}

// Service holds the dependencies needed for delegation service methods.
// Constructed once by root *theauth.TheAuth.New and reached via thin
// forwarders so the v2.0 public API surface keeps its exact signatures.
type Service struct {
	storage  Storage
	cfg      *Config
	resource ResourceLookup
	auditEm  audit.Emitter
	hooks    *obs.Hooks
}

// New constructs a delegation Service. cfg may be nil; in that case every
// public method returns the same "agent identity not configured" sentinel
// the legacy root code returned. em may be nil; the constructor swaps in
// audit.NoopEmitter.
func New(storage Storage, cfg *Config, resource ResourceLookup, em audit.Emitter) *Service {
	if em == nil {
		em = audit.NoopEmitter{}
	}
	return &Service{storage: storage, cfg: cfg, resource: resource, auditEm: em, hooks: &obs.Hooks{}}
}

// SetHooks installs the consumer-supplied observability bundle. Idempotent.
// Root *theauth.TheAuth wires this in New so every internal service shares
// the same Tracer + Metrics adapters.
func (s *Service) SetHooks(h *obs.Hooks) {
	if s == nil {
		return
	}
	if h == nil {
		h = &obs.Hooks{}
	}
	s.hooks = h
}

// errNotConfigured matches the legacy "theauth: agent identity not
// configured" sentinel returned by the root forwarders when the agent
// identity block is absent. Wrapped via fmt.Errorf so callers comparing
// strings (legacy tests) keep working.
var errNotConfigured = errors.New("theauth: agent identity not configured")

// GrantDelegation persists a delegation_grants row. Scope MUST be a subset
// of the configured ProtectedResource scopes; resource MUST match a known
// ProtectedResource identifier; max_duration_seconds MUST be > 0 and <=
// Config.MaxDelegationDuration. Returns models.ErrOAuthInvalidScope or
// models.ErrOAuthInvalidResource for the corresponding validation failures.
//
// Audit emission: delegation.granted with redacted metadata.
func (s *Service) GrantDelegation(ctx context.Context, in models.GrantDelegationInput) (grant models.DelegationGrant, err error) {
	if s == nil || s.cfg == nil {
		return models.DelegationGrant{}, errNotConfigured
	}
	ctx, span := s.hooks.StartSpan(ctx, obs.SpanDelegationGrant)
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
	s.auditEm.EmitAudit(ctx, "delegation.granted", models.TargetRef{Type: "delegation_grant", ID: stored.ID.String()}, map[string]any{
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
	if s == nil || s.cfg == nil {
		return nil, errNotConfigured
	}
	return s.storage.DelegationGrantsByUserID(ctx, userID)
}

// ListDelegationsForAgent returns every grant naming the supplied agent.
func (s *Service) ListDelegationsForAgent(ctx context.Context, agentID models.ULID) ([]models.DelegationGrant, error) {
	if s == nil || s.cfg == nil {
		return nil, errNotConfigured
	}
	return s.storage.DelegationGrantsByAgentID(ctx, agentID)
}

// RevokeDelegation marks a grant revoked. Cascade: every token already
// minted under this grant becomes invalid on the next resource server
// introspection refresh (worst case IntrospectionCacheTTL, default 60s).
//
// Audit emission: delegation.revoked.
func (s *Service) RevokeDelegation(ctx context.Context, grantID models.ULID, reason string) (err error) {
	if s == nil || s.cfg == nil {
		return errNotConfigured
	}
	ctx, span := s.hooks.StartSpan(ctx, obs.SpanDelegationRevoke)
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
	if err := s.storage.RevokeDelegationGrant(ctx, grantID, now, reason); err != nil {
		return fmt.Errorf("revoke delegation: %w", err)
	}
	s.auditEm.EmitAudit(ctx, "delegation.revoked", models.TargetRef{Type: "delegation_grant", ID: grantID.String()}, map[string]any{
		"grant_id": grantID.String(),
		"user_id":  cur.UserID.String(),
		"agent_id": cur.AgentID.String(),
		"resource": cur.Resource,
		"reason":   reason,
	})
	return nil
}

// GrantByID returns the persisted delegation grant. Exposed so handler-
// layer code can perform ownership checks (the legacy implementation
// reached through the root oauthStorage back-door; PR C removes that
// back-door in favour of this lookup). The storage error is returned
// unwrapped so callers can compare with models.ErrStorageNotFound.
func (s *Service) GrantByID(ctx context.Context, grantID models.ULID) (*models.DelegationGrant, error) {
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
// non-delegation code paths; collapsing them is out of scope for PR C).
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
