package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/internal/apitokens"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// grantRevoker is the optional storage surface the cascade uses to void an
// agent's delegation grants.
type grantRevoker interface {
	DelegationGrantsByAgentID(ctx context.Context, agentID models.ULID) ([]models.DelegationGrant, error)
	RevokeDelegationGrant(ctx context.Context, id models.ULID, at time.Time, reason string) error
}

// ownerTokenRevoker is the optional storage surface the cascade uses to void
// API tokens owned by the agent itself.
type ownerTokenRevoker interface {
	RevokeAPITokensByOwner(ctx context.Context, ownerID models.ULID, at time.Time) (int, error)
}

// mintedTokenStore is the optional storage surface that voids API tokens minted for the agent by
// MintAgentToken. Those tokens belong to the delegating user, so the owner revoke never reaches
// them.
type mintedTokenStore interface {
	APITokensByOwner(ctx context.Context, ownerID models.ULID) ([]apitokens.APIToken, error)
	ListAPITokens(ctx context.Context) ([]apitokens.APIToken, error)
	RevokeAPIToken(ctx context.Context, id models.ULID, at time.Time) error
}

// cascadeAgentRevocation voids the agent's grants, owned tokens and minted tokens, then emits the
// revocation events. It is idempotent, so a failed run can be retried.
func (s *Service) cascadeAgentRevocation(ctx context.Context, ag models.Agent, status, reason string, at time.Time) error {
	var errs []error
	grants, gerrs := s.revokeAgentGrants(ctx, ag, status, reason, at)
	errs = append(errs, gerrs...)
	tokens := 0
	if tr, ok := s.storage.(ownerTokenRevoker); ok {
		n, err := tr.RevokeAPITokensByOwner(ctx, ag.ID, at)
		if err != nil {
			errs = append(errs, fmt.Errorf("revoke agent api tokens: %w", err))
		}
		tokens = n
	}
	minted, err := s.revokeMintedTokens(ctx, ag, status, at)
	if err != nil {
		errs = append(errs, err)
	}
	tokens += minted
	if grants > 0 || tokens > 0 {
		s.emitAgentEvent(ctx, "agent.cascade.revoked", ag, map[string]any{
			"agent_id":       ag.ID.String(),
			"status":         status,
			"reason":         reason,
			"grants_revoked": grants,
			"tokens_revoked": tokens,
		})
	}
	return errors.Join(errs...)
}

func (s *Service) revokeAgentGrants(ctx context.Context, ag models.Agent, status, reason string, at time.Time) (int, []error) {
	gr, ok := s.storage.(grantRevoker)
	if !ok {
		return 0, nil
	}
	var errs []error
	list, err := gr.DelegationGrantsByAgentID(ctx, ag.ID)
	if err != nil {
		errs = append(errs, fmt.Errorf("list agent grants: %w", err))
	}
	n := 0
	for _, g := range list {
		if g.RevokedAt != nil {
			continue
		}
		if err := gr.RevokeDelegationGrant(ctx, g.ID, at, "agent_"+status); err != nil {
			errs = append(errs, fmt.Errorf("revoke grant %s: %w", g.ID, err))
			continue
		}
		n++
		s.auditEm.EmitAudit(ctx, "delegation.revoked", models.TargetRef{Type: "delegation_grant", ID: g.ID.String()}, map[string]any{
			"grant_id": g.ID.String(),
			"user_id":  g.UserID.String(),
			"agent_id": ag.ID.String(),
			"resource": g.Resource,
			"reason":   reason,
		})
	}
	return n, errs
}

// agentTokenLister is the optional storage surface that lists the API tokens
// minted for one agent id.
type agentTokenLister interface {
	APITokensByAgentID(ctx context.Context, agentID models.ULID) ([]apitokens.APIToken, error)
}

// revokeMintedTokens revokes the live agent-kind API tokens minted for ag and returns how many.
// Tokens matched by AgentID go first. A legacy name-and-owner fallback covers rows with no AgentID
// and never touches a token whose AgentID is set.
func (s *Service) revokeMintedTokens(ctx context.Context, ag models.Agent, status string, at time.Time) (int, error) {
	ts, ok := s.storage.(mintedTokenStore)
	if !ok {
		return 0, nil
	}
	var (
		errs []error
		n    int
	)
	revoke := func(t apitokens.APIToken) {
		if t.Kind != apitokens.APITokenKindAgent || t.RevokedAt != nil {
			return
		}
		if err := ts.RevokeAPIToken(ctx, t.ID, at); err != nil {
			errs = append(errs, fmt.Errorf("revoke minted token %s: %w", t.ID, err))
			return
		}
		n++
		s.auditEm.EmitAudit(ctx, "api_token.revoked", models.TargetRef{Type: "api_token", ID: t.ID.String()}, map[string]any{
			"token_id": t.ID.String(),
			"owner_id": t.OwnerID.String(),
			"agent_id": ag.ID.String(),
			"reason":   "agent_" + status,
		})
	}
	if al, ok := s.storage.(agentTokenLister); ok {
		exact, err := al.APITokensByAgentID(ctx, ag.ID)
		if err != nil {
			errs = append(errs, fmt.Errorf("list agent minted tokens by id: %w", err))
		}
		for _, t := range exact {
			revoke(t)
		}
	}
	var (
		list []apitokens.APIToken
		err  error
	)
	if ag.OwnerUserID != nil {
		list, err = ts.APITokensByOwner(ctx, *ag.OwnerUserID)
	} else {
		list, err = ts.ListAPITokens(ctx)
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("list agent minted tokens: %w", err))
		return n, errors.Join(errs...)
	}
	for _, t := range list {
		if t.AgentID != nil || t.AgentName != ag.Name {
			continue
		}
		if ag.OwnerUserID != nil && (t.DelegatedBy == nil || *t.DelegatedBy != *ag.OwnerUserID) {
			continue
		}
		revoke(t)
	}
	return n, errors.Join(errs...)
}
