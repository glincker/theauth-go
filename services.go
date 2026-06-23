package theauth

// services.go consolidates the OAuth, agent identity, and SAML service
// forwarders into a single file. PR I (2026-06-22) merged the prior
// service_oauth.go, service_agent.go, and service_saml.go files here so
// the repository root has fewer files and the README renders above the
// fold on GitHub. Every method below is a thin shim over the matching
// internal/<flow>.Service; substantive logic lives in those packages.
// Public API surface and signatures are byte-stable.

import (
	"context"
	"errors"
	"time"

	"github.com/glincker/theauth-go/internal/agent"
	internalsaml "github.com/glincker/theauth-go/internal/saml"
)

// ---------- Agent identity (validation + forwarders) ----------

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
// and AgentBySubjectClaim) into internal/agent. The exported method
// signatures on *TheAuth are unchanged so handlers and consumer code
// keep compiling. PR B's oauthStorage back-door is removed by this PR
// because every storage call now flows through internal/agent.
//
// PR G (2026-06-21) removed the unexported agentBySubjectClaim
// forwarder. The AgentLookup adapter wired in theauth.New now points
// directly at a.agentSvc.AgentBySubjectClaim (see theauth.go), so the
// root shim was dead.

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

// ---------- OAuth provider (start/callback forwarders) ----------

// service_oauth.go: thin forwarder shim around the extracted
// internal/oauth.Service. PR H (2026-06-22) moved the implementation of
// the OAuth start/callback state machine (oauthStateGCLoop, startOAuth,
// callbackOAuth, findOrCreateOAuthUser) into internal/oauth/service.go.
// Root keeps these unexported methods so that the oauthServiceAdapter in
// mounts_extracted.go (which satisfies the internal/oauth/handlers.Service
// interface) continues to compile without modification. Public API surface
// is byte-stable.

// startOAuth delegates the /auth/providers/{name}/start flow to
// the extracted internal/oauth.Service.
func (a *TheAuth) startOAuth(ctx context.Context, providerName string) (authURL, state string, err error) {
	return a.oauthSvc.Start(ctx, providerName)
}

// callbackOAuth delegates the /auth/providers/{name}/callback flow to
// the extracted internal/oauth.Service.
func (a *TheAuth) callbackOAuth(ctx context.Context, providerName, code, state, userAgent, ip string) (sessionToken string, user *User, err error) {
	return a.oauthSvc.Callback(ctx, providerName, code, state, userAgent, ip)
}

// ---------- SAML connections + SP-flow forwarders ----------

// SAML forwarders. PR D architecture reorg (2026-06-20) moved the
// implementations to internal/saml; the public CreateSAMLConnection /
// UpdateSAMLConnection / DeleteSAMLConnection / SAMLConnectionByID /
// ListSAMLConnections / BeginSAMLLogin / FinishSAMLLogin /
// SAMLMetadataXML entry points kept their exact signatures so callers in
// this package (handlers_saml) continue to compile unchanged.

// SAMLConnectionInput is the consumer-facing payload for create / update.
// Mirrors internal/saml.SAMLConnectionInput field-for-field so the public
// type is unchanged.
type SAMLConnectionInput struct {
	OrganizationID ULID
	IdPEntityID    string
	IdPSSOURL      string
	IdPX509Cert    string
	SPEntityID     string
	SPACSURL       string
	AttributeMap   SAMLAttributeMap
}

// toInternal projects the root-facing input type into the internal one.
// Mirror-shape; reuses the same field set.
func (in SAMLConnectionInput) toInternal() internalsaml.SAMLConnectionInput {
	return internalsaml.SAMLConnectionInput{
		OrganizationID: in.OrganizationID,
		IdPEntityID:    in.IdPEntityID,
		IdPSSOURL:      in.IdPSSOURL,
		IdPX509Cert:    in.IdPX509Cert,
		SPEntityID:     in.SPEntityID,
		SPACSURL:       in.SPACSURL,
		AttributeMap:   in.AttributeMap,
	}
}

// CreateSAMLConnection inserts a fresh saml_connections row.
func (a *TheAuth) CreateSAMLConnection(ctx context.Context, in SAMLConnectionInput) (SAMLConnection, error) {
	return a.samlSvc.CreateConnection(ctx, in.toInternal())
}

// UpdateSAMLConnection rewrites an existing connection in place.
func (a *TheAuth) UpdateSAMLConnection(ctx context.Context, id ULID, in SAMLConnectionInput) (SAMLConnection, error) {
	return a.samlSvc.UpdateConnection(ctx, id, in.toInternal())
}

// DeleteSAMLConnection removes the connection + cascades its identities.
func (a *TheAuth) DeleteSAMLConnection(ctx context.Context, id ULID) error {
	return a.samlSvc.DeleteConnection(ctx, id)
}

// SAMLConnectionByID looks up one connection.
func (a *TheAuth) SAMLConnectionByID(ctx context.Context, id ULID) (*SAMLConnection, error) {
	return a.samlSvc.ConnectionByID(ctx, id)
}

// ListSAMLConnections returns every connection for one organization.
func (a *TheAuth) ListSAMLConnections(ctx context.Context, orgID ULID) ([]SAMLConnection, error) {
	return a.samlSvc.ListConnections(ctx, orgID)
}

// BeginSAMLLogin returns the redirect URL for an SP-initiated SSO.
func (a *TheAuth) BeginSAMLLogin(ctx context.Context, connectionID ULID, relayState string) (string, error) {
	return a.samlSvc.BeginLogin(ctx, connectionID, relayState)
}

// FinishSAMLLogin validates an inbound SAMLResponse, runs find-or-create,
// issues a session, and returns its token.
func (a *TheAuth) FinishSAMLLogin(ctx context.Context, connectionID ULID, samlResponseB64 string, ua, ip string) (string, Session, error) {
	return a.samlSvc.FinishLogin(ctx, connectionID, samlResponseB64, ua, ip)
}

// SAMLMetadataXML serialises the per-connection SP metadata as XML.
func (a *TheAuth) SAMLMetadataXML(ctx context.Context, connectionID ULID) ([]byte, error) {
	return a.samlSvc.MetadataXML(ctx, connectionID)
}

// ensureOrgMembership upserts a "member" role row when the user is not
// already a member of the supplied organization. Used by the SCIM handler
// when an idempotent POST should re-enable a soft-deleted member. The
// SAML service has its own copy because internal/saml owns its own
// Storage interface; keeping this small helper on root means the SCIM
// handler does not need to import internal/saml.
func (a *TheAuth) ensureOrgMembership(ctx context.Context, orgID, userID ULID) error {
	_, err := a.storage.OrganizationMemberRole(ctx, orgID, userID)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrStorageNotFound) {
		return err
	}
	return a.storage.UpsertOrganizationMember(ctx, OrganizationMember{
		OrganizationID: orgID,
		UserID:         userID,
		Role:           OrgRoleMember,
	})
}
