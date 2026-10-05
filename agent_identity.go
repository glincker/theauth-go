package theauth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ErrAgentIdentityDisabled is returned when RegisterAgent runs without Config.AgentIdentity.
var ErrAgentIdentityDisabled = errors.New("theauth: agent identity is not enabled in Config")

// withActorChain adds the acting agent and its human to audit metadata so one
// event records both. It copies, never mutating the caller's map.
func withActorChain(ctx context.Context, md map[string]any) map[string]any {
	p, ok := PrincipalFromContext(ctx)
	if !ok || p.AgentName == "" {
		return md
	}
	out := make(map[string]any, len(md)+4)
	for k, v := range md {
		out[k] = v
	}
	out["actor_agent"] = p.AgentName
	out["actor_token_id"] = tokenIDString(p.TokenID)
	if p.DelegatedBy != nil {
		out["delegated_by"] = p.DelegatedBy.String()
	}
	out["actor_chain"] = p.ActorChain()
	return out
}

// MintAgentTokenInput describes a short-lived delegated credential for an agent.
type MintAgentTokenInput struct {
	// UserID is the human the agent acts for.
	UserID    ULID
	AgentName string
	// Abilities are the agent's allowed abilities. Each must be one the user
	// holds now; at request time the token is further cut to what the user
	// holds then.
	Abilities []string
	// TTL defaults to Config.APITokens.AgentTTL.
	TTL time.Duration
}

// MintAgentToken mints an API token with kind=agent acting for UserID. It
// returns ErrAbilityNotHeld when Abilities exceeds what the user holds now.
// Needs Config.APITokens.
func (a *TheAuth) MintAgentToken(ctx context.Context, in MintAgentTokenInput) (string, APIToken, error) {
	s, err := a.apiSvc()
	if err != nil {
		return "", APIToken{}, err
	}
	user, err := s.users.UserByID(ctx, in.UserID)
	if err != nil {
		return "", APIToken{}, fmt.Errorf("theauth: load delegating user: %w", err)
	}
	if err := s.validateAbilities(in.Abilities, false); err != nil {
		return "", APIToken{}, err
	}
	held, err := s.userAbilities(ctx, user)
	if err != nil {
		return "", APIToken{}, fmt.Errorf("theauth: resolve delegating user abilities: %w", err)
	}
	if len(clampAbilities(in.Abilities, held)) != len(in.Abilities) {
		return "", APIToken{}, ErrAbilityNotHeld
	}
	by := in.UserID
	raw, tok, err := s.mint(ctx, MintAPITokenInput{
		OwnerID: in.UserID, OwnerKind: OwnerKindUser, Name: in.AgentName, Abilities: in.Abilities, TTL: in.TTL,
		Kind: APITokenKindAgent, AgentName: in.AgentName, DelegatedBy: &by,
	})
	if err != nil {
		return "", APIToken{}, err
	}
	a.RecordTokenMinted(ctx, in.UserID, APITokenKindAgent)
	return raw, tok, nil
}

// DelegatedAbilities returns the intersection of an agent's allowed scopes
// and what the user holds right now, for resource servers that authenticate
// agents by another path (for example an OAuth access token) and want the same
// per-request cut as agent API tokens. Needs Config.APITokens.
func (a *TheAuth) DelegatedAbilities(ctx context.Context, userID ULID, agentScopes []string) ([]string, error) {
	s, err := a.apiSvc()
	if err != nil {
		return nil, err
	}
	user, err := s.users.UserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("theauth: load delegating user: %w", err)
	}
	held, err := s.userAbilities(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("theauth: resolve delegating user abilities: %w", err)
	}
	return clampAbilities(agentScopes, held), nil
}

// RegisterAgentInput describes an agent or MCP client to register under a human.
type RegisterAgentInput struct {
	OwnerID     ULID
	Name        string
	Description string
	// Scope is the set of scopes the agent may ever act with.
	Scope []string
	// Resource, when set, also records a delegation grant from the owner to
	// the agent for Scope on that resource.
	Resource string
	// MaxDuration bounds a delegated token's life under the grant. Defaults to
	// Config.AgentIdentity.DefaultDelegatedTokenTTL.
	MaxDuration time.Duration
	// GrantExpiresAt optionally ends the grant.
	GrantExpiresAt *time.Time
}

// AgentRegistration is the result of RegisterAgent. Secret is shown once.
type AgentRegistration struct {
	Agent  Agent
	Secret AgentSecret
	Grant  *DelegationGrant
}

// RegisterAgent creates an agent owned by a user and, when Resource is set,
// the delegation grant that lets it exchange tokens for that user. Needs
// Config.AgentIdentity and Config.AuthorizationServer.
func (a *TheAuth) RegisterAgent(ctx context.Context, in RegisterAgentInput) (AgentRegistration, error) {
	if a.agentSvc == nil || a.delegationSvc == nil || a.agentCfg == nil {
		return AgentRegistration{}, ErrAgentIdentityDisabled
	}
	owner := in.OwnerID
	ag, secret, err := a.agentSvc.CreateAgent(ctx, CreateAgentInput{
		Owner: AgentOwner{UserID: &owner}, Name: in.Name, Description: in.Description, Scope: slices.Clone(in.Scope),
	})
	if err != nil {
		return AgentRegistration{}, fmt.Errorf("theauth: register agent: %w", err)
	}
	reg := AgentRegistration{Agent: ag, Secret: secret}
	if in.Resource == "" {
		return reg, nil
	}
	dur := in.MaxDuration
	if dur <= 0 {
		dur = a.agentCfg.DefaultDelegatedTokenTTL
	}
	if dur <= 0 {
		dur = 15 * time.Minute
	}
	g, err := a.delegationSvc.GrantDelegation(ctx, GrantDelegationInput{
		UserID: in.OwnerID, AgentID: ag.ID, Scope: in.Scope, Resource: in.Resource,
		MaxDurationSeconds: int(dur.Seconds()), ExpiresAt: in.GrantExpiresAt,
	})
	if err != nil {
		return reg, fmt.Errorf("theauth: grant delegation for registered agent %s: %w", ag.ID, err)
	}
	reg.Grant = &g
	return reg, nil
}
