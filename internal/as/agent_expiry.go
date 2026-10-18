package as

import (
	"time"

	"github.com/glincker/theauth-go/v2/internal/chain"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// agentLiveErr reports why an agent may not act at now: ErrAgentExpired when its ExpiresAt has
// passed, ErrAgentInactive when it is suspended or revoked, nil when it is live. Both errors match
// ErrAgentInactive, so callers that only care about inactivity keep working, and ErrAgentExpired
// stays distinguishable (agent_expired).
func agentLiveErr(ag *models.Agent, now time.Time) error {
	if ag == nil {
		return models.ErrAgentInactive
	}
	if ag.Status != models.AgentStatusActive {
		return models.ErrAgentInactive
	}
	if ag.AgentExpired(now) {
		return models.ErrAgentExpired
	}
	return nil
}

// agentLive reports whether the agent is active and not expired at now.
func agentLive(ag *models.Agent, now time.Time) bool {
	return agentLiveErr(ag, now) == nil
}

// agentExpiryBound returns the agent's expiry, or the zero time when it has none. The zero value
// is ignored by chain.TightenDuration, so the result can be passed straight in as a candidate.
func agentExpiryBound(ag *models.Agent) time.Time {
	if ag == nil || ag.ExpiresAt == nil {
		return time.Time{}
	}
	return *ag.ExpiresAt
}

// capExpiry lowers exp to the earliest agent expiry in bounds.
func capExpiry(exp time.Time, bounds ...time.Time) time.Time {
	return chain.TightenDuration(append([]time.Time{exp}, bounds...)...)
}
