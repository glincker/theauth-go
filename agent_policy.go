package theauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/internal/agent"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
)

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
// policy. Without PolicyEngine and RateLimit it returns nil.
func (a *TheAuth) AuthorizeAgent(ctx context.Context, agentID, action, resource string) error {
	if a == nil || a.agentGate == nil {
		return nil
	}
	return a.agentGate.Authorize(ctx, agentID, action, resource)
}

// CheckAgentRate spends one unit of the agent's rate budget without evaluating policy; it suits
// toolguard.Guard.Limit.
func (a *TheAuth) CheckAgentRate(ctx context.Context, agentID string) error {
	if a == nil || a.agentGate == nil {
		return nil
	}
	return a.agentGate.CheckRate(ctx, agentID)
}
