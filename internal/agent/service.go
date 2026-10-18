// Package agent owns the agent identity lifecycle. It is a leaf: internal/as reaches it through
// AgentLookup, and cache invalidation is passed in as a function so this package never imports
// internal/as.
package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	oklogulid "github.com/oklog/ulid/v2"
)

// ChainDepthCeiling is the v2.0 hard cap on the actor chain length. The spec forbids raising it above 3.
const ChainDepthCeiling = 3

// Storage is the minimal persistence subset this package needs. It is declared here so the package
// does not import root.
type Storage interface {
	InsertOAuthClient(ctx context.Context, c models.OAuthClient) (models.OAuthClient, error)
	OAuthClientByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error)
	UpdateOAuthClient(ctx context.Context, c models.OAuthClient) (models.OAuthClient, error)
	DeleteOAuthClient(ctx context.Context, clientID string) error

	InsertAgent(ctx context.Context, a models.Agent) (models.Agent, error)
	AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error)
	AgentsByOwner(ctx context.Context, owner models.AgentOwner) ([]models.Agent, error)
	UpdateAgentStatus(ctx context.Context, id models.ULID, status string, at time.Time) error
	UpdateAgentExpiry(ctx context.Context, id models.ULID, expiresAt *time.Time) error

	InsertAgentCredential(ctx context.Context, c models.AgentCredential) error
	AgentCredentialsByAgentID(ctx context.Context, agentID models.ULID) ([]models.AgentCredential, error)
	RevokeAgentCredential(ctx context.Context, id models.ULID, at time.Time) error
}

// CacheInvalidator drops cached verified client entries for client_id, after a secret rotates or an
// insert fails.
type CacheInvalidator func(clientID string)

// ChainCacheInvalidator drops the introspection chain-walk cache entry for an agent. It runs on
// suspend and revoke, so a stale active result is never served.
type ChainCacheInvalidator func(agentID string)

// Config is the subset of AgentConfig the lifecycle code consults.
type Config struct {
	MaxChainDepth            int
	MaxDelegationDuration    time.Duration
	DefaultDelegatedTokenTTL time.Duration
	AgentSecretLength        int
}

// Service holds the dependencies of the agent lifecycle methods. Root constructs it and reaches it
// through thin forwarders.
type Service struct {
	storage         Storage
	cfg             *Config
	auditEm         audit.Emitter
	invalidate      CacheInvalidator
	invalidateChain ChainCacheInvalidator
	hooks           *obs.Hooks
	now             func() time.Time
}

// New constructs an agent Service. Nil cfg makes every method return the "agent identity not
// configured" sentinel. Nil collaborators are replaced with no-ops, so callers never need to
// branch.
func New(storage Storage, cfg *Config, em audit.Emitter, invalidate CacheInvalidator) *Service {
	if em == nil {
		em = audit.NoopEmitter{}
	}
	if invalidate == nil {
		invalidate = func(string) {}
	}
	return &Service{
		storage:         storage,
		cfg:             cfg,
		auditEm:         em,
		invalidate:      invalidate,
		invalidateChain: func(string) {},
		hooks:           &obs.Hooks{},
		now:             time.Now,
	}
}

// SetChainCacheInvalidator wires the chain-walk cache invalidator. It must run before any suspend
// or revoke, so a status change never leaves a stale cached result. Safe to call more than once.
func (s *Service) SetChainCacheInvalidator(fn ChainCacheInvalidator) {
	if s == nil || fn == nil {
		return
	}
	s.invalidateChain = fn
}

// SetHooks installs the observability bundle. It is idempotent and reaches every internal service this way.
func (s *Service) SetHooks(h *obs.Hooks) {
	if s == nil {
		return
	}
	if h == nil {
		h = &obs.Hooks{}
	}
	s.hooks = h
}

// instrument wraps an agent lifecycle entry in a span and status attribute. Callers defer the
// returned func to close the span with the named error.
func (s *Service) instrument(ctx context.Context, name string) (context.Context, obs.Span, func(err error)) {
	if s == nil {
		return ctx, obs.NoopSpan{}, func(error) {}
	}
	ctx, span := s.hooks.StartSpan(ctx, name)
	finish := func(err error) {
		status := obs.StatusSuccess
		if err != nil {
			status = obs.StatusError
			span.RecordError(err)
		}
		span.SetAttributes(obs.StringAttr(obs.AttrStatus, string(status)))
		span.End()
	}
	return ctx, span, finish
}

// errNotConfigured is the sentinel for an absent agent identity block.
var errNotConfigured = errors.New("theauth: agent identity not configured")

// CreateAgent persists an agent owned by a user or organization, mints its OAuth client and secret,
// and returns the agent and the one-shot secret. It emits agent.created (no secret material) and
// agent_credential.minted.
func (s *Service) CreateAgent(ctx context.Context, in models.CreateAgentInput) (agentRow models.Agent, agentSecret models.AgentSecret, err error) {
	if s == nil || s.cfg == nil {
		return models.Agent{}, models.AgentSecret{}, errNotConfigured
	}
	ctx, _, finish := s.instrument(ctx, obs.SpanAgentCreate)
	defer func() { finish(err) }()
	if verr := validateAgentOwner(in.Owner); verr != nil {
		err = verr
		return models.Agent{}, models.AgentSecret{}, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return models.Agent{}, models.AgentSecret{}, errors.New("theauth: agent name is required")
	}
	if verr := s.validateExpiry(in.ExpiresAt); verr != nil {
		return models.Agent{}, models.AgentSecret{}, verr
	}
	clientID := "agent-" + ulid.New().String()
	secret, err := crypto.NewToken()
	if err != nil {
		return models.Agent{}, models.AgentSecret{}, fmt.Errorf("generate agent secret: %w", err)
	}
	secretHash, err := crypto.HashPassword(secret)
	if err != nil {
		return models.Agent{}, models.AgentSecret{}, fmt.Errorf("hash agent secret: %w", err)
	}
	now := time.Now().UTC()
	agentID := ulid.New()
	owner := models.ClientOwner{AgentID: &agentID}
	client := models.OAuthClient{
		ID:                      ulid.New(),
		ClientID:                clientID,
		ClientSecretHash:        []byte(secretHash),
		ClientName:              name,
		GrantTypes:              []string{models.GrantTypeClientCredentials, models.GrantTypeTokenExchange},
		ResponseTypes:           []string{},
		Scope:                   strings.Join(in.Scope, " "),
		TokenEndpointAuthMethod: models.ClientAuthSecretBasic,
		ApplicationType:         "service",
		Owner:                   owner,
		CreatedAt:               now,
		UpdatedAt:               now,
	}
	if _, err := s.storage.InsertOAuthClient(ctx, client); err != nil {
		return models.Agent{}, models.AgentSecret{}, fmt.Errorf("persist agent oauth client: %w", err)
	}
	agent := models.Agent{
		ID:             agentID,
		OwnerUserID:    in.Owner.UserID,
		OrganizationID: in.Owner.OrganizationID,
		Name:           name,
		Description:    in.Description,
		Status:         models.AgentStatusActive,
		ClientID:       clientID,
		Scope:          append([]string(nil), in.Scope...),
		CreatedAt:      now,
		ExpiresAt:      cloneTime(in.ExpiresAt),
	}
	stored, err := s.storage.InsertAgent(ctx, agent)
	if err != nil {
		// Best-effort cleanup of the orphan client row. Failure is tolerated, since the unique client_id
		// blocks collisions.
		_ = s.storage.DeleteOAuthClient(ctx, clientID)
		// The client row was inserted and then deleted, so an in-flight authenticate may have cached it.
		// Drop the entry explicitly.
		s.invalidate(clientID)
		return models.Agent{}, models.AgentSecret{}, fmt.Errorf("persist agent: %w", err)
	}
	credID := ulid.New()
	cred := models.AgentCredential{
		ID:        credID,
		AgentID:   stored.ID,
		Kind:      models.AgentCredentialKindSecret,
		ValueEnc:  []byte(secretHash),
		CreatedAt: now,
	}
	if err := s.storage.InsertAgentCredential(ctx, cred); err != nil {
		return models.Agent{}, models.AgentSecret{}, fmt.Errorf("persist agent credential: %w", err)
	}
	s.emitAgentEvent(ctx, "agent.created", stored, map[string]any{
		"agent_id":  stored.ID.String(),
		"client_id": stored.ClientID,
		"owner":     ownerKindFor(stored),
	})
	s.emitAgentEvent(ctx, "agent_credential.minted", stored, map[string]any{
		"agent_id":      stored.ID.String(),
		"credential_id": credID.String(),
		"kind":          models.AgentCredentialKindSecret,
	})
	return stored, models.AgentSecret{
		AgentID:      stored.ID,
		CredentialID: credID,
		ClientID:     clientID,
		Secret:       secret,
	}, nil
}

// MintAgentCredential mints a credential of the requested kind on an existing agent. Only the
// secret kind is implemented; x509 and jwk return ErrNotImplemented. It emits
// agent_credential.minted.
func (s *Service) MintAgentCredential(ctx context.Context, agentID models.ULID, kind string) (models.AgentSecret, error) {
	if s == nil || s.cfg == nil {
		return models.AgentSecret{}, errNotConfigured
	}
	if kind == "" {
		kind = models.AgentCredentialKindSecret
	}
	if kind != models.AgentCredentialKindSecret {
		return models.AgentSecret{}, models.ErrNotImplemented
	}
	agent, err := s.storage.AgentByID(ctx, agentID)
	if err != nil {
		return models.AgentSecret{}, models.ErrAgentNotFound
	}
	if agent.Status == models.AgentStatusRevoked {
		return models.AgentSecret{}, models.ErrAgentInactive
	}
	secret, err := crypto.NewToken()
	if err != nil {
		return models.AgentSecret{}, fmt.Errorf("generate agent secret: %w", err)
	}
	secretHash, err := crypto.HashPassword(secret)
	if err != nil {
		return models.AgentSecret{}, fmt.Errorf("hash agent secret: %w", err)
	}
	now := time.Now().UTC()
	credID := ulid.New()
	if err := s.storage.InsertAgentCredential(ctx, models.AgentCredential{
		ID:        credID,
		AgentID:   agentID,
		Kind:      models.AgentCredentialKindSecret,
		ValueEnc:  []byte(secretHash),
		CreatedAt: now,
	}); err != nil {
		return models.AgentSecret{}, fmt.Errorf("persist agent credential: %w", err)
	}
	// Update the OAuthClient row to use the latest secret so /oauth/token
	// client authentication accepts the fresh secret immediately.
	client, err := s.storage.OAuthClientByClientID(ctx, agent.ClientID)
	if err != nil {
		return models.AgentSecret{}, fmt.Errorf("load agent oauth client: %w", err)
	}
	client.ClientSecretHash = []byte(secretHash)
	if _, err := s.storage.UpdateOAuthClient(ctx, *client); err != nil {
		return models.AgentSecret{}, fmt.Errorf("update agent oauth client: %w", err)
	}
	// The verified-client cache is keyed by client_id, so a rotated secret must drop the entry or the
	// old secret keeps working until it expires.
	s.invalidate(agent.ClientID)
	s.emitAgentEvent(ctx, "agent_credential.minted", *agent, map[string]any{
		"agent_id":      agent.ID.String(),
		"credential_id": credID.String(),
		"kind":          models.AgentCredentialKindSecret,
	})
	return models.AgentSecret{
		AgentID:      agent.ID,
		CredentialID: credID,
		ClientID:     agent.ClientID,
		Secret:       secret,
	}, nil
}

// RotateAgentSecret mints a fresh secret and revokes every prior credential. Use it on suspected
// compromise; use MintAgentCredential for overlapping credentials.
func (s *Service) RotateAgentSecret(ctx context.Context, agentID models.ULID) (models.AgentSecret, error) {
	if s == nil || s.cfg == nil {
		return models.AgentSecret{}, errNotConfigured
	}
	priors, err := s.storage.AgentCredentialsByAgentID(ctx, agentID)
	if err != nil {
		return models.AgentSecret{}, fmt.Errorf("load prior credentials: %w", err)
	}
	fresh, err := s.MintAgentCredential(ctx, agentID, models.AgentCredentialKindSecret)
	if err != nil {
		return models.AgentSecret{}, err
	}
	now := time.Now().UTC()
	for _, p := range priors {
		if p.RevokedAt != nil {
			continue
		}
		if err := s.storage.RevokeAgentCredential(ctx, p.ID, now); err != nil {
			// log via audit emission below; keep going so we revoke as many
			// priors as we can.
			s.emitAgentEvent(ctx, "agent_credential.revoke_failed", models.Agent{ID: agentID}, map[string]any{
				"agent_id":      agentID.String(),
				"credential_id": p.ID.String(),
				"err":           err.Error(),
			})
			continue
		}
		s.emitAgentEvent(ctx, "agent_credential.revoked", models.Agent{ID: agentID}, map[string]any{
			"agent_id":      agentID.String(),
			"credential_id": p.ID.String(),
			"reason":        "rotated",
		})
	}
	return fresh, nil
}

// ListAgentsByOwner returns every agent the supplied owner has created.
func (s *Service) ListAgentsByOwner(ctx context.Context, owner models.AgentOwner) ([]models.Agent, error) {
	if s == nil || s.cfg == nil {
		return nil, errNotConfigured
	}
	if err := validateAgentOwner(owner); err != nil {
		return nil, err
	}
	return s.storage.AgentsByOwner(ctx, owner)
}

// validateExpiry accepts nil (no expiry) or a time in the future that is no more than
// models.MaxAgentLifetime ahead.
func (s *Service) validateExpiry(at *time.Time) error {
	if at == nil {
		return nil
	}
	now := s.now()
	if !at.After(now) || at.After(now.Add(models.MaxAgentLifetime)) {
		return models.ErrAgentExpiryInvalid
	}
	return nil
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := t.UTC()
	return &c
}

// SetAgentExpiry sets the agent's expiry, or clears it with nil. A non-nil value must be in the
// future and within models.MaxAgentLifetime. Extending an expired agent revives it, unless it was
// suspended or revoked. It emits agent.expiry_changed.
func (s *Service) SetAgentExpiry(ctx context.Context, agentID models.ULID, expiresAt *time.Time) error {
	if s == nil || s.cfg == nil {
		return errNotConfigured
	}
	if err := s.validateExpiry(expiresAt); err != nil {
		return err
	}
	cur, err := s.storage.AgentByID(ctx, agentID)
	if err != nil {
		return models.ErrAgentNotFound
	}
	expiresAt = cloneTime(expiresAt)
	if err := s.storage.UpdateAgentExpiry(ctx, agentID, expiresAt); err != nil {
		return fmt.Errorf("update agent expiry: %w", err)
	}
	// A shortened expiry must take effect on the next authenticate and introspection, not after the
	// cached entries age out.
	s.invalidate(cur.ClientID)
	s.invalidateChain(cur.ID.String())
	meta := map[string]any{"agent_id": agentID.String()}
	if expiresAt != nil {
		meta["expires_at"] = expiresAt.Format(time.RFC3339)
	} else {
		meta["expires_at"] = nil
	}
	s.emitAgentEvent(ctx, "agent.expiry_changed", *cur, meta)
	return nil
}

// GetAgent returns the agent record by ID.
func (s *Service) GetAgent(ctx context.Context, agentID models.ULID) (*models.Agent, error) {
	if s == nil || s.cfg == nil {
		return nil, errNotConfigured
	}
	ag, err := s.storage.AgentByID(ctx, agentID)
	if err != nil {
		return nil, models.ErrAgentNotFound
	}
	return ag, nil
}

// SuspendAgent sets status to suspended. Tokens with this agent in their actor chain go inactive on
// the next introspection.
func (s *Service) SuspendAgent(ctx context.Context, agentID models.ULID, reason string) (err error) {
	ctx, _, finish := s.instrument(ctx, obs.SpanAgentSuspend)
	defer func() { finish(err) }()
	err = s.changeAgentStatus(ctx, agentID, models.AgentStatusSuspended, "agent.suspended", reason)
	return err
}

// ResumeAgent flips status back to active. Only valid on a suspended agent;
// resuming a revoked agent returns ErrAgentInactive.
func (s *Service) ResumeAgent(ctx context.Context, agentID models.ULID) error {
	cur, err := s.storage.AgentByID(ctx, agentID)
	if err != nil {
		return models.ErrAgentNotFound
	}
	if cur.Status == models.AgentStatusRevoked {
		return models.ErrAgentInactive
	}
	return s.changeAgentStatus(ctx, agentID, models.AgentStatusActive, "agent.resumed", "")
}

// RevokeAgent sets status to revoked. It is terminal: operators create a fresh agent instead of resuming.
func (s *Service) RevokeAgent(ctx context.Context, agentID models.ULID, reason string) (err error) {
	ctx, _, finish := s.instrument(ctx, obs.SpanAgentRevoke)
	defer func() { finish(err) }()
	err = s.changeAgentStatus(ctx, agentID, models.AgentStatusRevoked, "agent.revoked", reason)
	return err
}

func (s *Service) changeAgentStatus(ctx context.Context, agentID models.ULID, status, action, reason string) error {
	if s == nil || s.cfg == nil {
		return errNotConfigured
	}
	cur, err := s.storage.AgentByID(ctx, agentID)
	if err != nil {
		return models.ErrAgentNotFound
	}
	now := time.Now().UTC()
	if err := s.storage.UpdateAgentStatus(ctx, agentID, status, now); err != nil {
		return fmt.Errorf("update agent status: %w", err)
	}
	// A suspended or revoked agent must not authenticate from the verified-client cache, nor show
	// active in a chain-walk result.
	if status != models.AgentStatusActive {
		s.invalidate(cur.ClientID)
		s.invalidateChain(cur.ID.String())
	}
	meta := map[string]any{
		"agent_id": agentID.String(),
		"from":     cur.Status,
		"to":       status,
		"reason":   reason,
	}
	s.emitAgentEvent(ctx, action, *cur, meta)
	if status != models.AgentStatusActive {
		return s.cascadeAgentRevocation(ctx, *cur, status, reason, now)
	}
	return nil
}

// AgentByID returns the persisted agent row, for ownership checks in handler code. The storage
// error is returned unwrapped.
func (s *Service) AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error) {
	return s.storage.AgentByID(ctx, id)
}

// AgentBySubjectClaim resolves "agent:<id>" to its agent row. It returns (nil, nil) when the claim
// names no agent. It satisfies internal/as.AgentLookup.
func (s *Service) AgentBySubjectClaim(ctx context.Context, sub string) (*models.Agent, error) {
	if s == nil {
		return nil, nil
	}
	if !strings.HasPrefix(sub, models.AgentSubjectPrefix) {
		return nil, nil
	}
	idStr := strings.TrimPrefix(sub, models.AgentSubjectPrefix)
	id, err := oklogulid.Parse(idStr)
	if err != nil {
		return nil, models.ErrAgentNotFound
	}
	return s.storage.AgentByID(ctx, id)
}

// emitAgentEvent emits an agent audit event with the target set to agent:<id>, and the owner kind
// in metadata for filtering.
func (s *Service) emitAgentEvent(ctx context.Context, action string, ag models.Agent, meta map[string]any) {
	s.auditEm.EmitAudit(ctx, action, models.TargetRef{Type: "agent", ID: ag.ID.String()}, meta)
}

func validateAgentOwner(o models.AgentOwner) error {
	hasUser := o.UserID != nil
	hasOrg := o.OrganizationID != nil
	if hasUser == hasOrg {
		return errors.New("theauth: AgentOwner must specify exactly one of UserID or OrganizationID")
	}
	return nil
}

func ownerKindFor(ag models.Agent) string {
	if ag.OwnerUserID != nil {
		return "user"
	}
	if ag.OrganizationID != nil {
		return "organization"
	}
	return "unknown"
}
