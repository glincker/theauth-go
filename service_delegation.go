package theauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/internal/chain"
	"github.com/glincker/theauth-go/internal/ulid"
)

// service_delegation.go: delegation grant lifecycle (v2.0 phase 4).
//
// A delegation grant records that user U has authorized agent A to act on
// their behalf on resource R, capped to scope_grant and max_duration. Token
// exchange consults the row at every mint; revocation flips revoked_at and
// makes every derived token invalid on next introspection.
//
// RBAC: callers MUST gate the user_id parameter on the authenticated user
// (or an organization admin acting in scope). The service surface itself
// does not enforce that gate; the future /account/delegations and
// /admin/v1/delegations handlers (phase 6) do.

// GrantDelegation persists a delegation_grants row. Scope MUST be a subset
// of the configured ProtectedResource scopes; resource MUST match a known
// ProtectedResource identifier; max_duration_seconds MUST be > 0 and <=
// AgentConfig.MaxDelegationDuration. Returns ErrOAuthInvalidScope or
// ErrOAuthInvalidResource for the corresponding validation failures.
//
// Audit emission: delegation.granted with redacted metadata.
func (a *TheAuth) GrantDelegation(ctx context.Context, in GrantDelegationInput) (DelegationGrant, error) {
	if a.as == nil || a.agentCfg == nil {
		return DelegationGrant{}, errors.New("theauth: agent identity not configured")
	}
	if in.Resource == "" {
		return DelegationGrant{}, ErrOAuthInvalidResource
	}
	resource, ok := a.resourceByIdentifier(in.Resource)
	if !ok {
		return DelegationGrant{}, ErrOAuthInvalidResource
	}
	if len(in.Scope) == 0 {
		return DelegationGrant{}, ErrOAuthInvalidScope
	}
	if _, err := validateScopeAgainstResource(in.Scope, resource); err != nil {
		return DelegationGrant{}, err
	}
	if in.MaxDurationSeconds <= 0 {
		return DelegationGrant{}, errors.New("theauth: GrantDelegation MaxDurationSeconds must be > 0")
	}
	cap := int(a.agentCfg.MaxDelegationDuration.Seconds())
	if in.MaxDurationSeconds > cap {
		return DelegationGrant{}, fmt.Errorf("theauth: MaxDurationSeconds exceeds policy cap %d", cap)
	}
	// Verify the agent exists and is active before we record any approval.
	ag, err := a.as.storage.AgentByID(ctx, in.AgentID)
	if err != nil {
		return DelegationGrant{}, ErrAgentNotFound
	}
	if ag.Status != AgentStatusActive {
		return DelegationGrant{}, ErrAgentInactive
	}
	now := time.Now().UTC()
	row := DelegationGrant{
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
	stored, err := a.as.storage.InsertDelegationGrant(ctx, row)
	if err != nil {
		return DelegationGrant{}, fmt.Errorf("persist delegation grant: %w", err)
	}
	a.EmitAudit(ctx, "delegation.granted", TargetRef{Type: "delegation_grant", ID: stored.ID.String()}, map[string]any{
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
func (a *TheAuth) ListDelegationsForUser(ctx context.Context, userID ULID) ([]DelegationGrant, error) {
	if a.as == nil || a.agentCfg == nil {
		return nil, errors.New("theauth: agent identity not configured")
	}
	return a.as.storage.DelegationGrantsByUserID(ctx, userID)
}

// ListDelegationsForAgent returns every grant naming the supplied agent.
func (a *TheAuth) ListDelegationsForAgent(ctx context.Context, agentID ULID) ([]DelegationGrant, error) {
	if a.as == nil || a.agentCfg == nil {
		return nil, errors.New("theauth: agent identity not configured")
	}
	return a.as.storage.DelegationGrantsByAgentID(ctx, agentID)
}

// RevokeDelegation marks a grant revoked. Cascade: every token already
// minted under this grant becomes invalid on the next resource server
// introspection refresh (worst case IntrospectionCacheTTL, default 60s).
//
// Audit emission: delegation.revoked.
func (a *TheAuth) RevokeDelegation(ctx context.Context, grantID ULID, reason string) error {
	if a.as == nil || a.agentCfg == nil {
		return errors.New("theauth: agent identity not configured")
	}
	cur, err := a.as.storage.DelegationGrantByID(ctx, grantID)
	if err != nil {
		return ErrDelegationNotFound
	}
	if cur.RevokedAt != nil {
		// Idempotent: a second revoke is a no-op.
		return nil
	}
	now := time.Now().UTC()
	if err := a.as.storage.RevokeDelegationGrant(ctx, grantID, now, reason); err != nil {
		return fmt.Errorf("revoke delegation: %w", err)
	}
	a.EmitAudit(ctx, "delegation.revoked", TargetRef{Type: "delegation_grant", ID: grantID.String()}, map[string]any{
		"grant_id": grantID.String(),
		"user_id":  cur.UserID.String(),
		"agent_id": cur.AgentID.String(),
		"resource": cur.Resource,
		"reason":   reason,
	})
	return nil
}

// delegationActive reports whether the supplied grant is currently usable
// for token exchange: not revoked and not past its expires_at envelope (if
// set). Token exchange + introspection both call this on every check to
// keep cascade revocation observable inside IntrospectionCacheTTL.
func delegationActive(g *DelegationGrant, now time.Time) bool {
	if g == nil || g.RevokedAt != nil {
		return false
	}
	if g.ExpiresAt != nil && !now.Before(*g.ExpiresAt) {
		return false
	}
	return true
}

// narrowDelegatedScope returns the strict intersection of (requested,
// subject_scope, grant_scope). Empty result means the caller asked for
// nothing the chain still allows; the token-exchange path treats that as
// invalid_scope.
func narrowDelegatedScope(requested, subjectScope, grantScope []string) ([]string, bool) {
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
