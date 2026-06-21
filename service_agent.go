package theauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
	oklogulid "github.com/oklog/ulid/v2"
)

// service_agent.go: agent identity lifecycle (v2.0 phase 3).
//
// An agent is created by an owner (a user or an organization). At create
// time the AS mints an underlying OAuthClient row (owner_kind=agent,
// token_endpoint_auth_method=client_secret_basic), generates a fresh client
// secret, and stores its Argon2id hash twice: once on the OAuthClient row
// (so the existing /oauth/token client authentication path works
// unchanged) and once on an agent_credentials row (so rotation history is
// preserved and so future X.509 / JWK credential kinds slot into the same
// table). The plaintext secret is returned to the caller exactly once.

// chainDepthCeiling is the v2.0 hard cap on the actor chain length. The
// spec explicitly forbids raising this above 3 in v2.0.
const chainDepthCeiling = 3

// validateAgentConfig applies defaults and screens fields. Mutates cfg in
// place.
func validateAgentConfig(cfg *AgentConfig) error {
	if cfg == nil {
		return nil
	}
	if cfg.MaxChainDepth == 0 {
		cfg.MaxChainDepth = chainDepthCeiling
	}
	if cfg.MaxChainDepth < 1 {
		cfg.MaxChainDepth = 1
	}
	if cfg.MaxChainDepth > chainDepthCeiling {
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

// CreateAgent persists a fresh agent owned by the supplied user or
// organization, mints a backing OAuthClient + client secret, records the
// secret on an agent_credentials row, and returns both the Agent record and
// the one-shot AgentSecret. Audit emission: agent.created (without secret
// material) plus agent_credential.minted.
func (a *TheAuth) CreateAgent(ctx context.Context, in CreateAgentInput) (Agent, AgentSecret, error) {
	if a.as == nil || a.agentCfg == nil {
		return Agent{}, AgentSecret{}, errors.New("theauth: agent identity not configured")
	}
	if err := validateAgentOwner(in.Owner); err != nil {
		return Agent{}, AgentSecret{}, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return Agent{}, AgentSecret{}, errors.New("theauth: agent name is required")
	}
	clientID := "agent-" + ulid.New().String()
	secret, err := crypto.NewToken()
	if err != nil {
		return Agent{}, AgentSecret{}, fmt.Errorf("generate agent secret: %w", err)
	}
	secretHash, err := crypto.HashPassword(secret)
	if err != nil {
		return Agent{}, AgentSecret{}, fmt.Errorf("hash agent secret: %w", err)
	}
	now := time.Now().UTC()
	agentID := ulid.New()
	owner := ClientOwner{AgentID: &agentID}
	client := OAuthClient{
		ID:                      ulid.New(),
		ClientID:                clientID,
		ClientSecretHash:        []byte(secretHash),
		ClientName:              name,
		GrantTypes:              []string{GrantTypeClientCredentials, GrantTypeTokenExchange},
		ResponseTypes:           []string{},
		Scope:                   scopeJoin(in.Scope),
		TokenEndpointAuthMethod: ClientAuthSecretBasic,
		ApplicationType:         "service",
		Owner:                   owner,
		CreatedAt:               now,
		UpdatedAt:               now,
	}
	if _, err := a.as.storage.InsertOAuthClient(ctx, client); err != nil {
		return Agent{}, AgentSecret{}, fmt.Errorf("persist agent oauth client: %w", err)
	}
	agent := Agent{
		ID:             agentID,
		OwnerUserID:    in.Owner.UserID,
		OrganizationID: in.Owner.OrganizationID,
		Name:           name,
		Description:    in.Description,
		Status:         AgentStatusActive,
		ClientID:       clientID,
		Scope:          append([]string(nil), in.Scope...),
		CreatedAt:      now,
	}
	stored, err := a.as.storage.InsertAgent(ctx, agent)
	if err != nil {
		// Best-effort cleanup of the orphan oauth_clients row; failing
		// silently is acceptable because the unique client_id prevents a
		// retry from colliding and the operator can sweep stragglers via
		// the admin API in a later phase.
		_ = a.as.storage.DeleteOAuthClient(ctx, clientID)
		return Agent{}, AgentSecret{}, fmt.Errorf("persist agent: %w", err)
	}
	credID := ulid.New()
	cred := AgentCredential{
		ID:        credID,
		AgentID:   stored.ID,
		Kind:      AgentCredentialKindSecret,
		ValueEnc:  []byte(secretHash),
		CreatedAt: now,
	}
	if err := a.as.storage.InsertAgentCredential(ctx, cred); err != nil {
		return Agent{}, AgentSecret{}, fmt.Errorf("persist agent credential: %w", err)
	}
	a.emitAgentEvent(ctx, "agent.created", stored, map[string]any{
		"agent_id":  stored.ID.String(),
		"client_id": stored.ClientID,
		"owner":     ownerKindFor(stored),
	})
	a.emitAgentEvent(ctx, "agent_credential.minted", stored, map[string]any{
		"agent_id":      stored.ID.String(),
		"credential_id": credID.String(),
		"kind":          AgentCredentialKindSecret,
	})
	return stored, AgentSecret{
		AgentID:      stored.ID,
		CredentialID: credID,
		ClientID:     clientID,
		Secret:       secret,
	}, nil
}

// MintAgentCredential mints a fresh credential of the requested kind on an
// existing agent. Only kind = AgentCredentialKindSecret is implemented in
// phase 3; X.509 and JWK kinds return ErrNotImplemented so callers see a
// typed error rather than silent success. Audit emission:
// agent_credential.minted on success.
func (a *TheAuth) MintAgentCredential(ctx context.Context, agentID ULID, kind string) (AgentSecret, error) {
	if a.as == nil || a.agentCfg == nil {
		return AgentSecret{}, errors.New("theauth: agent identity not configured")
	}
	if kind == "" {
		kind = AgentCredentialKindSecret
	}
	if kind != AgentCredentialKindSecret {
		return AgentSecret{}, ErrNotImplemented
	}
	agent, err := a.as.storage.AgentByID(ctx, agentID)
	if err != nil {
		return AgentSecret{}, ErrAgentNotFound
	}
	if agent.Status == AgentStatusRevoked {
		return AgentSecret{}, ErrAgentInactive
	}
	secret, err := crypto.NewToken()
	if err != nil {
		return AgentSecret{}, fmt.Errorf("generate agent secret: %w", err)
	}
	secretHash, err := crypto.HashPassword(secret)
	if err != nil {
		return AgentSecret{}, fmt.Errorf("hash agent secret: %w", err)
	}
	now := time.Now().UTC()
	credID := ulid.New()
	if err := a.as.storage.InsertAgentCredential(ctx, AgentCredential{
		ID:        credID,
		AgentID:   agentID,
		Kind:      AgentCredentialKindSecret,
		ValueEnc:  []byte(secretHash),
		CreatedAt: now,
	}); err != nil {
		return AgentSecret{}, fmt.Errorf("persist agent credential: %w", err)
	}
	// Update the OAuthClient row to use the latest secret so /oauth/token
	// client authentication accepts the fresh secret immediately.
	client, err := a.as.storage.OAuthClientByClientID(ctx, agent.ClientID)
	if err != nil {
		return AgentSecret{}, fmt.Errorf("load agent oauth client: %w", err)
	}
	client.ClientSecretHash = []byte(secretHash)
	if _, err := a.as.storage.UpdateOAuthClient(ctx, *client); err != nil {
		return AgentSecret{}, fmt.Errorf("update agent oauth client: %w", err)
	}
	a.emitAgentEvent(ctx, "agent_credential.minted", *agent, map[string]any{
		"agent_id":      agent.ID.String(),
		"credential_id": credID.String(),
		"kind":          AgentCredentialKindSecret,
	})
	return AgentSecret{
		AgentID:      agent.ID,
		CredentialID: credID,
		ClientID:     agent.ClientID,
		Secret:       secret,
	}, nil
}

// RotateAgentSecret is an alias for MintAgentCredential(kind="secret") that
// also revokes every prior unrevoked credential. Use this on suspected
// compromise; use MintAgentCredential when overlapping live credentials are
// the desired migration shape.
func (a *TheAuth) RotateAgentSecret(ctx context.Context, agentID ULID) (AgentSecret, error) {
	if a.as == nil || a.agentCfg == nil {
		return AgentSecret{}, errors.New("theauth: agent identity not configured")
	}
	priors, err := a.as.storage.AgentCredentialsByAgentID(ctx, agentID)
	if err != nil {
		return AgentSecret{}, fmt.Errorf("load prior credentials: %w", err)
	}
	fresh, err := a.MintAgentCredential(ctx, agentID, AgentCredentialKindSecret)
	if err != nil {
		return AgentSecret{}, err
	}
	now := time.Now().UTC()
	for _, p := range priors {
		if p.RevokedAt != nil {
			continue
		}
		if err := a.as.storage.RevokeAgentCredential(ctx, p.ID, now); err != nil {
			// log via audit emission below; keep going so we revoke as many
			// priors as we can.
			a.emitAgentEvent(ctx, "agent_credential.revoke_failed", Agent{ID: agentID}, map[string]any{
				"agent_id":      agentID.String(),
				"credential_id": p.ID.String(),
				"err":           err.Error(),
			})
			continue
		}
		a.emitAgentEvent(ctx, "agent_credential.revoked", Agent{ID: agentID}, map[string]any{
			"agent_id":      agentID.String(),
			"credential_id": p.ID.String(),
			"reason":        "rotated",
		})
	}
	return fresh, nil
}

// ListAgentsByOwner returns every agent the supplied owner has created.
func (a *TheAuth) ListAgentsByOwner(ctx context.Context, owner AgentOwner) ([]Agent, error) {
	if a.as == nil || a.agentCfg == nil {
		return nil, errors.New("theauth: agent identity not configured")
	}
	if err := validateAgentOwner(owner); err != nil {
		return nil, err
	}
	return a.as.storage.AgentsByOwner(ctx, owner)
}

// GetAgent returns the agent record by ID.
func (a *TheAuth) GetAgent(ctx context.Context, agentID ULID) (*Agent, error) {
	if a.as == nil || a.agentCfg == nil {
		return nil, errors.New("theauth: agent identity not configured")
	}
	ag, err := a.as.storage.AgentByID(ctx, agentID)
	if err != nil {
		return nil, ErrAgentNotFound
	}
	return ag, nil
}

// SuspendAgent flips status to suspended. Cascades: every existing access
// token mentioning this agent in its actor chain becomes inactive on the
// next introspection refresh.
func (a *TheAuth) SuspendAgent(ctx context.Context, agentID ULID, reason string) error {
	return a.changeAgentStatus(ctx, agentID, AgentStatusSuspended, "agent.suspended", reason)
}

// ResumeAgent flips status back to active. Only valid on a suspended agent;
// resuming a revoked agent returns ErrAgentInactive.
func (a *TheAuth) ResumeAgent(ctx context.Context, agentID ULID) error {
	cur, err := a.as.storage.AgentByID(ctx, agentID)
	if err != nil {
		return ErrAgentNotFound
	}
	if cur.Status == AgentStatusRevoked {
		return ErrAgentInactive
	}
	return a.changeAgentStatus(ctx, agentID, AgentStatusActive, "agent.resumed", "")
}

// RevokeAgent flips status to revoked. Terminal: a revoked agent cannot be
// resumed (operators create a fresh agent instead). Cascades to every token
// in flight via introspection on next refresh.
func (a *TheAuth) RevokeAgent(ctx context.Context, agentID ULID, reason string) error {
	return a.changeAgentStatus(ctx, agentID, AgentStatusRevoked, "agent.revoked", reason)
}

func (a *TheAuth) changeAgentStatus(ctx context.Context, agentID ULID, status, action, reason string) error {
	if a.as == nil || a.agentCfg == nil {
		return errors.New("theauth: agent identity not configured")
	}
	cur, err := a.as.storage.AgentByID(ctx, agentID)
	if err != nil {
		return ErrAgentNotFound
	}
	now := time.Now().UTC()
	if err := a.as.storage.UpdateAgentStatus(ctx, agentID, status, now); err != nil {
		return fmt.Errorf("update agent status: %w", err)
	}
	meta := map[string]any{
		"agent_id": agentID.String(),
		"from":     cur.Status,
		"to":       status,
		"reason":   reason,
	}
	a.emitAgentEvent(ctx, action, *cur, meta)
	return nil
}

// emitAgentEvent is a thin EmitAudit wrapper that stamps the target as
// agent:<id> and surfaces the agent's owner kind in metadata for downstream
// filtering. EmitAudit handles the audit-disabled, audit-closed, and
// channel-full cases on its own.
func (a *TheAuth) emitAgentEvent(ctx context.Context, action string, ag Agent, meta map[string]any) {
	a.EmitAudit(ctx, action, TargetRef{Type: "agent", ID: ag.ID.String()}, meta)
}

func validateAgentOwner(o AgentOwner) error {
	hasUser := o.UserID != nil
	hasOrg := o.OrganizationID != nil
	if hasUser == hasOrg {
		return errors.New("theauth: AgentOwner must specify exactly one of UserID or OrganizationID")
	}
	return nil
}

func ownerKindFor(ag Agent) string {
	if ag.OwnerUserID != nil {
		return "user"
	}
	if ag.OrganizationID != nil {
		return "organization"
	}
	return "unknown"
}

// agentBySubjectClaim parses a sub or act.sub of the form "agent:<id>" and
// returns the corresponding agent row. Returns (nil, nil) when the claim
// does not name an agent so callers can branch cleanly.
func (a *TheAuth) agentBySubjectClaim(ctx context.Context, sub string) (*Agent, error) {
	if a.as == nil {
		return nil, nil
	}
	if !strings.HasPrefix(sub, AgentSubjectPrefix) {
		return nil, nil
	}
	idStr := strings.TrimPrefix(sub, AgentSubjectPrefix)
	id, err := oklogulid.Parse(idStr)
	if err != nil {
		return nil, ErrAgentNotFound
	}
	return a.as.storage.AgentByID(ctx, id)
}
