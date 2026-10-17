package apitokens

import (
	"context"
	"fmt"
	"time"
)

// WithActorChain adds the acting agent and its human to audit metadata so one
// event records both. It copies, never mutating the caller's map.
func WithActorChain(ctx context.Context, md map[string]any) map[string]any {
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
	// AgentID is the registered agent the token is minted for. Set it whenever the agent is known, so
	// suspend and revoke cut the token by exact id. Nil keeps a name-only record.
	AgentID *ULID
	// Abilities are the agent's allowed abilities. Each must be held by the user now, and the token is
	// cut further to what the user holds at request time.
	Abilities []string
	// TTL defaults to Config.APITokens.AgentTTL.
	TTL time.Duration
}

// MintAgentToken mints an agent-kind API token acting for UserID. It returns ErrAbilityNotHeld when
// Abilities exceeds the user's.
func (s *Service) MintAgentToken(ctx context.Context, in MintAgentTokenInput) (string, APIToken, error) {
	user, err := s.users.UserByID(ctx, in.UserID)
	if err != nil {
		return "", APIToken{}, fmt.Errorf("theauth: load delegating user: %w", err)
	}
	if err := s.validateAbilities(in.Abilities, false); err != nil {
		return "", APIToken{}, err
	}
	held, err := s.UserAbilities(ctx, user)
	if err != nil {
		return "", APIToken{}, fmt.Errorf("theauth: resolve delegating user abilities: %w", err)
	}
	if len(clampAbilities(in.Abilities, held)) != len(in.Abilities) {
		return "", APIToken{}, ErrAbilityNotHeld
	}
	by := in.UserID
	raw, tok, err := s.Mint(ctx, MintAPITokenInput{
		OwnerID: in.UserID, OwnerKind: OwnerKindUser, Name: in.AgentName, Abilities: in.Abilities, TTL: in.TTL,
		Kind: APITokenKindAgent, AgentName: in.AgentName, DelegatedBy: &by, AgentID: in.AgentID,
	})
	if err != nil {
		return "", APIToken{}, err
	}
	s.host.RecordTokenMinted(ctx, in.UserID, APITokenKindAgent)
	return raw, tok, nil
}

// DelegatedAbilities returns the intersection of an agent's scopes and what the user holds now.
// Resource servers that authenticate agents another way use it for the same per-request cut.
func (s *Service) DelegatedAbilities(ctx context.Context, userID ULID, agentScopes []string) ([]string, error) {
	user, err := s.users.UserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("theauth: load delegating user: %w", err)
	}
	held, err := s.UserAbilities(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("theauth: resolve delegating user abilities: %w", err)
	}
	return clampAbilities(agentScopes, held), nil
}
