package theauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/internal/agent"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
	"github.com/glincker/theauth-go/v2/policy/hook"
	oklogulid "github.com/oklog/ulid/v2"
)

// AgentHookRunner runs AgentConfig.BeforeAuthorize: a before authorize hook or
// external guard with a timeout, panic recovery and fail closed. Build it with
// the policy/hook package, for example
// &hook.Runner{Hook: guard, Timeout: 1500 * time.Millisecond}.
type AgentHookRunner = hook.Runner

// AgentPolicyEngine resolves and evaluates the policies attached to an agent. Hosts normally use the
// agentpolicy package rather than implementing it.
type AgentPolicyEngine = agent.PolicyEngine

// AgentRateLimit bounds how often one agent may mint tokens or call Authorize:
// Requests per Per, with Burst as the bucket size (default Requests). The zero
// value disables the limit.
type AgentRateLimit struct {
	Requests int
	Per      time.Duration
	Burst    int
}

// Policy refusals and limits surfaced by AuthorizeAgent.
type (
	// AgentPolicyDeniedError is returned when an agent's policy refuses an
	// action. errors.Is(err, ErrAgentPolicyDenied) matches it.
	AgentPolicyDeniedError = models.AgentPolicyDeniedError
	// AgentRateLimitedError is returned when an agent used up its budget.
	AgentRateLimitedError = models.AgentRateLimitedError
)

// ErrAgentPolicyDenied is wrapped by every refusal caused by agent policy.
var ErrAgentPolicyDenied = models.ErrAgentPolicyDenied

// ErrAgentRateLimit is the sentinel for an invalid AgentConfig.RateLimit.
var ErrAgentRateLimit = errors.New("theauth: invalid AgentConfig.RateLimit")

func (r AgentRateLimit) window() ratelimit.Window {
	return ratelimit.Window{Requests: r.Requests, Per: r.Per, Burst: r.Burst}
}

func validateAgentRateLimit(r *AgentRateLimit) error {
	if *r == (AgentRateLimit{}) {
		return nil
	}
	n, err := r.Normalize()
	if err != nil {
		return err
	}
	*r = n
	return nil
}

// Normalize applies defaults (Per one minute, Burst equal to Requests) and rejects negative values and
// a non-positive Requests. The zero value is invalid: use a nil pointer for "no override".
func (r AgentRateLimit) Normalize() (AgentRateLimit, error) {
	if r.Requests < 0 || r.Per < 0 || r.Burst < 0 {
		return AgentRateLimit{}, fmt.Errorf("%w: negative value", ErrAgentRateLimit)
	}
	if r.Requests == 0 {
		return AgentRateLimit{}, fmt.Errorf("%w: Requests must be positive", ErrAgentRateLimit)
	}
	if r.Per == 0 {
		r.Per = time.Minute
	}
	if r.Burst == 0 {
		r.Burst = r.Requests
	}
	return r, nil
}

// AuthorizeAgent checks whether the agent may perform action on resource under its attached policies,
// spending one unit of its rate budget. It returns nil when allowed, *AgentPolicyDeniedError on refusal,
// *AgentRateLimitedError (with RetryAfter) when the budget is spent, and an error for an unresolvable
// policy. Without PolicyEngine, RateLimit and BeforeAuthorize it returns nil.
//
// With AgentConfig.BeforeAuthorize set, the hook runs after the policy and rate limit allowed the
// call. A refusal from it wraps ErrAgentPolicyDenied and a *hook.BlockedError carrying the decision
// code (hook_denied, hook_timeout, hook_error or approval_required), and emits an
// agent.authorize_denied audit event with decision_code.
func (a *TheAuth) AuthorizeAgent(ctx context.Context, agentID, action, resource string) error {
	if a == nil {
		return nil
	}
	if a.agentGate != nil {
		if err := a.agentGate.Authorize(ctx, agentID, action, resource); err != nil {
			return err
		}
	}
	return a.runBeforeAuthorize(ctx, agentID, action, resource)
}

// runBeforeAuthorize runs the configured hook. The agent is resolved first; an
// unknown or inactive agent, or a storage failure, refuses the call without
// asking the hook.
func (a *TheAuth) runBeforeAuthorize(ctx context.Context, agentID, action, resource string) error {
	if a.agentCfg == nil || a.agentCfg.BeforeAuthorize == nil {
		return nil
	}
	info, chain, err := a.AgentHookSubject(ctx, agentID)
	if err != nil {
		return err
	}
	out := a.agentCfg.BeforeAuthorize.Run(ctx, hook.Input{
		AgentID: agentID, Action: action, Resource: resource,
		Agent: info, Delegation: chain, Source: hook.SourceAuthorize,
	})
	if out.Allowed() {
		return nil
	}
	a.EmitAudit(ctx, "agent.authorize_denied", TargetRef{Type: "agent", ID: agentID}, map[string]any{
		"agent_id":      agentID,
		"action":        action,
		"resource":      resource,
		"effect":        string(out.Decision),
		"reason":        out.Reason,
		"decision_code": string(out.Code),
		"hook":          out.AuditRecord(),
	})
	return fmt.Errorf("%w: %w", ErrAgentPolicyDenied, out.Err())
}

// AgentHookSubject returns the agent and delegation fields of a hook input for agentID. The
// delegation path is the agent alone; Inbound lists the agent's active delegation grants. A Go grant
// runs from a user to an agent, so FromAgent holds "user:<id>". It fits toolguard.Guard.HookSubject.
// An unknown agent wraps ErrAgentNotFound and a suspended or revoked one ErrAgentInactive.
func (a *TheAuth) AgentHookSubject(ctx context.Context, agentID string) (hook.AgentInfo, hook.Delegation, error) {
	if a == nil || a.agentSvc == nil {
		return hook.AgentInfo{}, hook.Delegation{}, fmt.Errorf("%w: agent identity is not configured", ErrAgentNotFound)
	}
	id, err := oklogulid.Parse(agentID)
	if err != nil {
		return hook.AgentInfo{}, hook.Delegation{}, fmt.Errorf("%w: malformed agent id", ErrAgentNotFound)
	}
	ag, err := a.agentSvc.GetAgent(ctx, id)
	if err != nil {
		return hook.AgentInfo{}, hook.Delegation{}, err
	}
	if ag == nil {
		return hook.AgentInfo{}, hook.Delegation{}, ErrAgentNotFound
	}
	if ag.Status != AgentStatusActive {
		return hook.AgentInfo{}, hook.Delegation{}, fmt.Errorf("%w: %s", ErrAgentInactive, agentID)
	}
	info := hook.AgentInfo{ID: agentID, Name: ag.Name}
	switch {
	case ag.OwnerUserID != nil:
		info.OwnerID = ag.OwnerUserID.String()
		if ag.OrganizationID != nil {
			info.TenantID = ag.OrganizationID.String()
		}
	case ag.OrganizationID != nil:
		info.OwnerID = ag.OrganizationID.String()
		info.TenantID = info.OwnerID
	}
	chain := hook.Delegation{RootOwnerID: info.OwnerID, Path: []string{agentID}, Links: []hook.Link{}, Inbound: []hook.Link{}}
	if a.delegationSvc == nil {
		return info, chain, nil
	}
	grants, err := a.delegationSvc.ListDelegationsForAgent(ctx, id)
	if err != nil {
		return hook.AgentInfo{}, hook.Delegation{}, fmt.Errorf("theauth: load delegations for agent %s: %w", agentID, err)
	}
	maxDepth := 0
	if a.agentCfg != nil {
		maxDepth = a.agentCfg.MaxChainDepth
	}
	now := time.Now()
	for _, g := range grants {
		if g.RevokedAt != nil || (g.ExpiresAt != nil && !now.Before(*g.ExpiresAt)) {
			continue
		}
		chain.Inbound = append(chain.Inbound, hook.Link{
			DelegationID: g.ID.String(),
			FromAgent:    "user:" + g.UserID.String(),
			ToAgent:      agentID,
			Permissions:  []hook.Permission{{Resource: g.Resource, Actions: append([]string{}, g.Scope...)}},
			Depth:        1,
			MaxDepth:     maxDepth,
			ExpiresAt:    g.ExpiresAt,
			CreatedAt:    g.CreatedAt,
		})
	}
	return info, chain, nil
}

// CheckAgentRate spends one unit of the agent's rate budget without evaluating policy; it suits
// toolguard.Guard.Limit.
func (a *TheAuth) CheckAgentRate(ctx context.Context, agentID string) error {
	if a == nil || a.agentGate == nil {
		return nil
	}
	return a.agentGate.CheckRate(ctx, agentID)
}
