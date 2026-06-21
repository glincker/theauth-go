package theauth

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/internal/agent"
)

// validateAgentConfig applies defaults and screens fields. Mutates cfg in
// place. Mirrors the legacy root validateAgentConfig (removed when
// service_agent.go moved into internal/agent in PR C); the validation
// stays at the root layer because Config.AgentIdentity is a public type
// and the operator-visible defaults must be honoured before any internal
// service sees the values.
func validateAgentConfig(cfg *AgentConfig) error {
	if cfg == nil {
		return nil
	}
	if cfg.MaxChainDepth == 0 {
		cfg.MaxChainDepth = agent.ChainDepthCeiling
	}
	if cfg.MaxChainDepth < 1 {
		cfg.MaxChainDepth = 1
	}
	if cfg.MaxChainDepth > agent.ChainDepthCeiling {
		return ErrAgentChainDepthTooHigh
	}
	if cfg.MaxDelegationDuration <= 0 {
		cfg.MaxDelegationDuration = 90 * 24 * time.Hour
	}
	if cfg.DefaultDelegatedTokenTTL <= 0 {
		cfg.DefaultDelegatedTokenTTL = 15 * time.Minute
	}
	if cfg.AgentSecretLength <= 0 {
		cfg.AgentSecretLength = 32
	}
	return nil
}

// service_agent.go: thin forwarders into the extracted agent identity
// service. PR C of the 2026-06 architecture reorg moved the lifecycle
// implementation (CreateAgent, MintAgentCredential, RotateAgentSecret,
// ListAgentsByOwner, GetAgent, SuspendAgent, ResumeAgent, RevokeAgent,
// and agentBySubjectClaim) into internal/agent. The exported method
// signatures on *TheAuth are unchanged so handlers and consumer code
// keep compiling. PR B's oauthStorage back-door is removed by this PR
// because every storage call now flows through internal/agent.

// CreateAgent persists a fresh agent owned by the supplied user or
// organization, mints a backing OAuthClient + client secret, records the
// secret on an agent_credentials row, and returns both the Agent record
// and the one-shot AgentSecret.
func (a *TheAuth) CreateAgent(ctx context.Context, in CreateAgentInput) (Agent, AgentSecret, error) {
	return a.agentSvc.CreateAgent(ctx, in)
}

// MintAgentCredential mints a fresh credential of the requested kind on
// an existing agent. Only kind = AgentCredentialKindSecret is implemented
// in phase 3; X.509 and JWK kinds return ErrNotImplemented.
func (a *TheAuth) MintAgentCredential(ctx context.Context, agentID ULID, kind string) (AgentSecret, error) {
	return a.agentSvc.MintAgentCredential(ctx, agentID, kind)
}

// RotateAgentSecret mints a fresh secret credential and revokes every
// prior unrevoked credential. Use this on suspected compromise; use
// MintAgentCredential when overlapping live credentials are desired.
func (a *TheAuth) RotateAgentSecret(ctx context.Context, agentID ULID) (AgentSecret, error) {
	return a.agentSvc.RotateAgentSecret(ctx, agentID)
}

// ListAgentsByOwner returns every agent the supplied owner has created.
func (a *TheAuth) ListAgentsByOwner(ctx context.Context, owner AgentOwner) ([]Agent, error) {
	return a.agentSvc.ListAgentsByOwner(ctx, owner)
}

// GetAgent returns the agent record by ID.
func (a *TheAuth) GetAgent(ctx context.Context, agentID ULID) (*Agent, error) {
	return a.agentSvc.GetAgent(ctx, agentID)
}

// SuspendAgent flips status to suspended. Cascades to every issued token
// mentioning this agent on the next introspection refresh.
func (a *TheAuth) SuspendAgent(ctx context.Context, agentID ULID, reason string) error {
	return a.agentSvc.SuspendAgent(ctx, agentID, reason)
}

// ResumeAgent flips status back to active. Only valid on a suspended
// agent; resuming a revoked agent returns ErrAgentInactive.
func (a *TheAuth) ResumeAgent(ctx context.Context, agentID ULID) error {
	return a.agentSvc.ResumeAgent(ctx, agentID)
}

// RevokeAgent flips status to revoked. Terminal: a revoked agent cannot
// be resumed (operators create a fresh agent instead).
func (a *TheAuth) RevokeAgent(ctx context.Context, agentID ULID, reason string) error {
	return a.agentSvc.RevokeAgent(ctx, agentID, reason)
}

// agentBySubjectClaim resolves an "agent:<id>" sub or act.sub claim into
// the underlying Agent row. Returns (nil, nil) when the claim does not
// name an agent so callers can branch cleanly. The internal/as
// AgentLookup adapter is wired to this method at New time so the
// introspection and token-exchange paths never import internal/agent
// directly.
func (a *TheAuth) agentBySubjectClaim(ctx context.Context, sub string) (*Agent, error) {
	if a.agentSvc == nil {
		return nil, nil
	}
	return a.agentSvc.AgentBySubjectClaim(ctx, sub)
}
