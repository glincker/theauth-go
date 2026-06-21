package theauth

import (
	"context"
	"net/http"

	agenthandlers "github.com/glincker/theauth-go/internal/agent/handlers"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/go-chi/chi/v5"
)

// handlers_admin_agents.go: thin forwarder around the extracted
// internal/agent/handlers package. PR F architecture reorg
// (2026-06-20) moved the seven /admin/v1/.../{agents,delegations}
// endpoints there.

// adminAgentAdapter implements agenthandlers.AgentService on top of
// root *TheAuth.
type adminAgentAdapter struct{ a *TheAuth }

func (s adminAgentAdapter) ListAgentsByOwner(ctx context.Context, owner models.AgentOwner) ([]models.Agent, error) {
	return s.a.ListAgentsByOwner(ctx, owner)
}

func (s adminAgentAdapter) CreateAgent(ctx context.Context, in models.CreateAgentInput) (models.Agent, models.AgentSecret, error) {
	return s.a.CreateAgent(ctx, in)
}

func (s adminAgentAdapter) AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error) {
	return s.a.agentSvc.AgentByID(ctx, id)
}

func (s adminAgentAdapter) GetAgent(ctx context.Context, id models.ULID) (*models.Agent, error) {
	return s.a.GetAgent(ctx, id)
}

func (s adminAgentAdapter) SuspendAgent(ctx context.Context, agentID models.ULID, reason string) error {
	return s.a.SuspendAgent(ctx, agentID, reason)
}

func (s adminAgentAdapter) ResumeAgent(ctx context.Context, agentID models.ULID) error {
	return s.a.ResumeAgent(ctx, agentID)
}

func (s adminAgentAdapter) RevokeAgent(ctx context.Context, agentID models.ULID, reason string) error {
	return s.a.RevokeAgent(ctx, agentID, reason)
}

// adminDelegationAdapter implements
// agenthandlers.DelegationService on top of root *TheAuth.
type adminDelegationAdapter struct{ a *TheAuth }

func (s adminDelegationAdapter) ListDelegationsForUser(ctx context.Context, userID models.ULID) ([]models.DelegationGrant, error) {
	return s.a.ListDelegationsForUser(ctx, userID)
}

func (s adminDelegationAdapter) ListDelegationsForAgent(ctx context.Context, agentID models.ULID) ([]models.DelegationGrant, error) {
	return s.a.ListDelegationsForAgent(ctx, agentID)
}

func (s adminDelegationAdapter) GrantDelegation(ctx context.Context, in models.GrantDelegationInput) (models.DelegationGrant, error) {
	return s.a.GrantDelegation(ctx, in)
}

func (s adminDelegationAdapter) GrantByID(ctx context.Context, grantID models.ULID) (*models.DelegationGrant, error) {
	return s.a.delegationSvc.GrantByID(ctx, grantID)
}

func (s adminDelegationAdapter) RevokeDelegation(ctx context.Context, grantID models.ULID, reason string) error {
	return s.a.RevokeDelegation(ctx, grantID, reason)
}

// adminOrgAdapter implements agenthandlers.OrganizationLookup on top
// of the root storage.
type adminOrgAdapter struct{ a *TheAuth }

func (s adminOrgAdapter) OrganizationMemberRole(ctx context.Context, orgID, userID models.ULID) (string, error) {
	return s.a.storage.OrganizationMemberRole(ctx, orgID, userID)
}

// mountAdminAgents wires the agent + delegation routes via the
// extracted internal/agent/handlers package. Called from mountAdmin
// when the agent identity service is configured.
func (a *TheAuth) mountAdminAgents(r chi.Router) {
	if a.agentCfg == nil || a.as == nil {
		return
	}
	h := agenthandlers.New(
		adminAgentAdapter{a: a},
		adminDelegationAdapter{a: a},
		adminOrgAdapter{a: a},
	)
	h.Mount(r, func(permission string) func(http.Handler) http.Handler {
		return a.RequirePermission(permission)
	})
}
