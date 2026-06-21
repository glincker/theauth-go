package theauth

import (
	"context"
)

// service_delegation.go: thin forwarders into the extracted delegation
// service. PR C of the 2026-06 architecture reorg moved the implementation
// (GrantDelegation, ListDelegationsForUser, ListDelegationsForAgent,
// RevokeDelegation) into internal/delegation. The canonical delegationActive
// and narrowDelegatedScope helpers also live there (PR B had duplicates in
// both root and internal/as; PR C unifies on the internal/delegation copy).
// The exported method signatures on *TheAuth are unchanged so handlers and
// consumer code keep compiling. PR B's oauthStorage back-door is removed by
// this PR because every storage call now flows through internal/delegation.
//
// RBAC: callers MUST gate the user_id parameter on the authenticated user
// (or an organization admin acting in scope). The service surface itself
// does not enforce that gate; the /account/delegations and
// /admin/v1/delegations handlers (handlers_account.go,
// handlers_admin_agents.go) do.

// GrantDelegation persists a delegation_grants row. Scope MUST be a subset
// of the configured ProtectedResource scopes; resource MUST match a known
// ProtectedResource identifier; max_duration_seconds MUST be > 0 and <=
// AgentConfig.MaxDelegationDuration.
func (a *TheAuth) GrantDelegation(ctx context.Context, in GrantDelegationInput) (DelegationGrant, error) {
	return a.delegationSvc.GrantDelegation(ctx, in)
}

// ListDelegationsForUser returns every grant the user has issued,
// including revoked ones (for audit / display).
func (a *TheAuth) ListDelegationsForUser(ctx context.Context, userID ULID) ([]DelegationGrant, error) {
	return a.delegationSvc.ListDelegationsForUser(ctx, userID)
}

// ListDelegationsForAgent returns every grant naming the supplied agent.
func (a *TheAuth) ListDelegationsForAgent(ctx context.Context, agentID ULID) ([]DelegationGrant, error) {
	return a.delegationSvc.ListDelegationsForAgent(ctx, agentID)
}

// RevokeDelegation marks a grant revoked. Cascade: every token already
// minted under this grant becomes invalid on the next resource server
// introspection refresh (worst case IntrospectionCacheTTL, default 60s).
func (a *TheAuth) RevokeDelegation(ctx context.Context, grantID ULID, reason string) error {
	return a.delegationSvc.RevokeDelegation(ctx, grantID, reason)
}
