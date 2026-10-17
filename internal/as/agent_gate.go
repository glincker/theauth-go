package as

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// agent_gate.go: hook that lets the host attach IAM policy and a rate limit to
// agents. The gate vets every agent token mint; with no gate set nothing
// changes.

// AgentGate vets a token mint for an agent. Implemented by internal/agent.Gate.
type AgentGate interface {
	AuthorizeMint(ctx context.Context, ag models.Agent, req models.AgentMintRequest) (models.AgentMintResult, error)
}

// gateMint runs the gate, if any, and returns the surviving scopes. Rate limit
// refusals become *RateLimitedError so the token endpoint answers 429 with
// Retry-After. A nil gate returns scopes untouched.
func (s *Service) gateMint(ctx context.Context, ag models.Agent, grant, resource string, scopes []string, explicit bool, ceiling []string) (models.AgentMintResult, error) {
	if s.AgentGate == nil {
		return models.AgentMintResult{Scopes: scopes}, nil
	}
	res, err := s.AgentGate.AuthorizeMint(ctx, ag, models.AgentMintRequest{
		Grant: grant, Resource: resource, Scopes: scopes, Explicit: explicit, Ceiling: ceiling,
	})
	if err != nil {
		var rl *models.AgentRateLimitedError
		if errors.As(err, &rl) {
			return models.AgentMintResult{}, &RateLimitedError{RetryAfter: rl.RetryAfter}
		}
		return models.AgentMintResult{}, err
	}
	return res, nil
}

// agentPolicyClaim is the access token claim recording which policies vetted
// the mint. It is absent when no policy applied.
func agentPolicyClaim(res models.AgentMintResult) map[string]any {
	if len(res.PolicyIDs) == 0 && res.PolicyHash == "" {
		return nil
	}
	ids := res.PolicyIDs
	if ids == nil {
		ids = []string{}
	}
	return map[string]any{"ids": ids, "hash": res.PolicyHash}
}

// addAgentPolicy stamps the claim and audit metadata when a policy applied.
func addAgentPolicy(claims map[string]any, meta map[string]any, res models.AgentMintResult) {
	c := agentPolicyClaim(res)
	if c == nil {
		return
	}
	if claims != nil {
		claims["agent_policy"] = c
	}
	if meta != nil {
		meta["agent_policy"] = c
		if len(res.Dropped) > 0 {
			meta["policy_dropped_scopes"] = res.Dropped
		}
	}
}
