// Package agent owns the v2.0 agent identity lifecycle: CreateAgent,
// MintAgentCredential, RotateAgentSecret, ListAgentsByOwner, GetAgent,
// SuspendAgent, ResumeAgent, RevokeAgent, and the agentBySubjectClaim
// resolver consulted by internal/as. Extracted from root service_agent.go
// in PR C of the 2026-06 architecture reorg.
//
// Dependency direction: internal/agent is a leaf with respect to internal/as
// and internal/delegation. internal/as reaches back through the AgentLookup
// interface (set after construction so the wiring stays acyclic). The cache
// invalidation hook is a function-typed dependency so the agent package
// does not import internal/as.
package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/models"
	obs "github.com/glincker/theauth-go/internal/observability"
	"github.com/glincker/theauth-go/internal/ulid"
	oklogulid "github.com/oklog/ulid/v2"
)

// ChainDepthCeiling is the v2.0 hard cap on the actor chain length. The
// spec explicitly forbids raising this above 3 in v2.0. Kept exported so
// root validation can refer to the same constant.
const ChainDepthCeiling = 3

// Storage is the minimal persistence subset this package needs. Declared
// here (not imported from root) so internal/agent does not import
// github.com/glincker/theauth-go.
type Storage interface {
	InsertOAuthClient(ctx context.Context, c models.OAuthClient) (models.OAuthClient, error)
	OAuthClientByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error)
	UpdateOAuthClient(ctx context.Context, c models.OAuthClient) (models.OAuthClient, error)
	DeleteOAuthClient(ctx context.Context, clientID string) error

	InsertAgent(ctx context.Context, a models.Agent) (models.Agent, error)
	AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error)
	AgentsByOwner(ctx context.Context, owner models.AgentOwner) ([]models.Agent, error)
	UpdateAgentStatus(ctx context.Context, id models.ULID, status string, at time.Time) error

	InsertAgentCredential(ctx context.Context, c models.AgentCredential) error
	AgentCredentialsByAgentID(ctx context.Context, agentID models.ULID) ([]models.AgentCredential, error)
	RevokeAgentCredential(ctx context.Context, id models.ULID, at time.Time) error
}

// CacheInvalidator drops cached Argon2-verified entries for the supplied
// client_id. Used after the OAuthClient secret hash is rotated or after a
// failed insert so the next /oauth/token call sees the fresh state.
// Function-typed so the agent package never imports internal/as.
type CacheInvalidator func(clientID string)

// ChainCacheInvalidator drops the per-agent introspection chain-walk cache
// entry for the supplied agent ID string. Called from changeAgentStatus on
// suspend/revoke so the next introspection re-walks the chain instead of
// serving a stale "active" result (perf re-audit 2026-06-21, item 3).
// Function-typed so the agent package never imports internal/as.
type ChainCacheInvalidator func(agentID string)

// Config bundles the validated agent-identity policy fields this package
// needs at lifecycle time. Mirrors the subset of root AgentConfig the
// agent service actually consults.
type Config struct {
	MaxChainDepth            int
	MaxDelegationDuration    time.Duration
	DefaultDelegatedTokenTTL time.Duration
	AgentSecretLength        int
}

// Service holds the dependencies needed for agent lifecycle methods.
// Constructed once by root *theauth.TheAuth.New and reached via thin
// forwarders so the v2.0 public API surface keeps its exact signatures.
type Service struct {
	storage         Storage
	cfg             *Config
	auditEm         audit.Emitter
	invalidate      CacheInvalidator
	invalidateChain ChainCacheInvalidator
	hooks           *obs.Hooks
}

// New constructs an agent Service. cfg may be nil; in that case every
// public method returns the same "agent identity not configured" sentinel
// the legacy root code returned. em may be nil; the constructor swaps in
// audit.NoopEmitter. invalidate may be nil; the constructor swaps in a
// no-op so callers do not need to branch. invalidateChain may be nil;
// the constructor swaps in a no-op.
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
	}
}

// SetChainCacheInvalidator wires the chain-walk cache invalidator. Must
// be called before any SuspendAgent / RevokeAgent call to ensure the AS
// chain cache does not serve stale results after a status change
// (perf re-audit 2026-06-21, item 3). Safe to call multiple times.
func (s *Service) SetChainCacheInvalidator(fn ChainCacheInvalidator) {
	if s == nil || fn == nil {
		return
	}
	s.invalidateChain = fn
}

// SetHooks installs the consumer-supplied observability bundle. Idempotent;
// safe to call before the first lifecycle method. Root *theauth.TheAuth
// calls this in New after the agent Service is constructed so the same
// bundle reaches every internal service.
func (s *Service) SetHooks(h *obs.Hooks) {
	if s == nil {
		return
	}
	if h == nil {
		h = &obs.Hooks{}
	}
	s.hooks = h
}

// instrument wraps an agent-lifecycle entry in a span + status attribute
// triple. Returns a deferred function the caller invokes via defer to
// close the span with the function's named-return err.
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

// errNotConfigured matches the legacy "theauth: agent identity not
// configured" sentinel returned by the root forwarders when the agent
// identity block is absent.
var errNotConfigured = errors.New("theauth: agent identity not configured")

// CreateAgent persists a fresh agent owned by the supplied user or
// organization, mints a backing OAuthClient + client secret, records the
// secret on an agent_credentials row, and returns both the Agent record and
// the one-shot AgentSecret. Audit emission: agent.created (without secret
// material) plus agent_credential.minted.
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
	}
	stored, err := s.storage.InsertAgent(ctx, agent)
	if err != nil {
		// Best-effort cleanup of the orphan oauth_clients row; failing
		// silently is acceptable because the unique client_id prevents a
		// retry from colliding and the operator can sweep stragglers via
		// the admin API in a later phase.
		_ = s.storage.DeleteOAuthClient(ctx, clientID)
		// Cache invalidation contract (clientauthcache): the row was just
		// inserted and then deleted, so any in-flight authenticate call
		// could still have cached a verified snapshot. Drop it explicitly
		// so a future re-registration of the same client_id starts clean.
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

// MintAgentCredential mints a fresh credential of the requested kind on an
// existing agent. Only kind = AgentCredentialKindSecret is implemented in
// phase 3; X.509 and JWK kinds return ErrNotImplemented so callers see a
// typed error rather than silent success. Audit emission:
// agent_credential.minted on success.
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
	// Cache invalidation contract (clientauthcache): the verified-client
	// LRU is keyed by client_id and stores the prior secret's sha256
	// digest. Without this Invalidate, a hot client would continue to
	// authenticate with the OLD secret until the entry expired naturally.
	// RotateAgentSecret depends on the new secret taking effect on the
	// next /oauth/token call; that contract requires this line.
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

// RotateAgentSecret is an alias for MintAgentCredential(kind="secret") that
// also revokes every prior unrevoked credential. Use this on suspected
// compromise; use MintAgentCredential when overlapping live credentials are
// the desired migration shape.
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

// SuspendAgent flips status to suspended. Cascades: every existing access
// token mentioning this agent in its actor chain becomes inactive on the
// next introspection refresh.
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

// RevokeAgent flips status to revoked. Terminal: a revoked agent cannot be
// resumed (operators create a fresh agent instead). Cascades to every token
// in flight via introspection on next refresh.
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
	// Cache invalidation contract (clientauthcache + chain cache): a
	// suspended or revoked agent must not authenticate via a cached
	// Argon2-verified snapshot, and must not appear "active" in any cached
	// chain-walk result. Drop both entries so the next /oauth/token and
	// the next introspection see the fresh status (perf re-audit
	// 2026-06-21, item 3).
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
	return nil
}

// AgentByID returns the persisted agent row. Exposed so handler-layer code
// can perform ownership checks (the legacy implementation reached through
// the root oauthStorage back-door; PR C removes that back-door in favour
// of this lookup). The storage error is returned unwrapped so callers can
// compare with models.ErrStorageNotFound.
func (s *Service) AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error) {
	return s.storage.AgentByID(ctx, id)
}

// AgentBySubjectClaim parses a sub or act.sub of the form "agent:<id>"
// and returns the corresponding agent row. Returns (nil, nil) when the
// claim does not name an agent so callers can branch cleanly. Satisfies
// internal/as.AgentLookup so the AS introspection / token-exchange paths
// can validate chain actors without importing this package directly.
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

// emitAgentEvent is a thin EmitAudit wrapper that stamps the target as
// agent:<id> and surfaces the agent's owner kind in metadata for downstream
// filtering. EmitAudit handles the audit-disabled, audit-closed, and
// channel-full cases on its own.
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
