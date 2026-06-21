package theauth

import (
	"context"

	accounthandlers "github.com/glincker/theauth-go/internal/account/handlers"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/go-chi/chi/v5"
)

// handlers_account.go: thin forwarder around the extracted
// internal/account/handlers package. PR F architecture reorg
// (2026-06-20) moved the six /account/* end-user self-service
// endpoints there; this file keeps the mountAccount entrypoint and
// the two small adapters that bridge the *TheAuth surface to the
// handler-side service interfaces.

// accountAgentAdapter implements accounthandlers.AgentService on top
// of root *TheAuth. AgentByID forwards to the agentSvc field directly
// because the public *TheAuth surface does not expose an AgentByID
// method (only the wider GetAgent, which the handler uses on the
// admin path).
type accountAgentAdapter struct{ a *TheAuth }

func (s accountAgentAdapter) ListAgentsByOwner(ctx context.Context, owner models.AgentOwner) ([]models.Agent, error) {
	return s.a.ListAgentsByOwner(ctx, owner)
}

func (s accountAgentAdapter) CreateAgent(ctx context.Context, in models.CreateAgentInput) (models.Agent, models.AgentSecret, error) {
	return s.a.CreateAgent(ctx, in)
}

func (s accountAgentAdapter) AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error) {
	return s.a.agentSvc.AgentByID(ctx, id)
}

func (s accountAgentAdapter) RevokeAgent(ctx context.Context, agentID models.ULID, reason string) error {
	return s.a.RevokeAgent(ctx, agentID, reason)
}

// accountDelegationAdapter implements
// accounthandlers.DelegationService on top of root *TheAuth.
type accountDelegationAdapter struct{ a *TheAuth }

func (s accountDelegationAdapter) ListDelegationsForUser(ctx context.Context, userID models.ULID) ([]models.DelegationGrant, error) {
	return s.a.ListDelegationsForUser(ctx, userID)
}

func (s accountDelegationAdapter) GrantDelegation(ctx context.Context, in models.GrantDelegationInput) (models.DelegationGrant, error) {
	return s.a.GrantDelegation(ctx, in)
}

func (s accountDelegationAdapter) GrantByID(ctx context.Context, grantID models.ULID) (*models.DelegationGrant, error) {
	return s.a.delegationSvc.GrantByID(ctx, grantID)
}

func (s accountDelegationAdapter) RevokeDelegation(ctx context.Context, grantID models.ULID, reason string) error {
	return s.a.RevokeDelegation(ctx, grantID, reason)
}

// mountAccount wires the /account routes via the extracted
// internal/account/handlers package. Idempotent guard matches the
// legacy root: only fires when AccountUX, AgentIdentity, and the AS
// are all configured.
func (a *TheAuth) mountAccount(r chi.Router) {
	if !a.accountUX || a.agentCfg == nil || a.as == nil {
		return
	}
	h := accounthandlers.New(
		accountAgentAdapter{a: a},
		accountDelegationAdapter{a: a},
		userFromRequest,
	)
	h.Mount(r, a.RequireAuth())
}
