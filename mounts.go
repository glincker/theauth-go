package theauth

import (
	"context"
	"net/http"
	"time"

	accounthandlers "github.com/glincker/theauth-go/v2/internal/account"
	adminhandlers "github.com/glincker/theauth-go/v2/internal/admin"
	agenthandlers "github.com/glincker/theauth-go/v2/internal/agent/handlers"
	ashandlers "github.com/glincker/theauth-go/v2/internal/as/handlers"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/identitylink"
	"github.com/glincker/theauth-go/v2/internal/models"
	orghandlers "github.com/glincker/theauth-go/v2/internal/organizations/handlers"
	samlhandlers "github.com/glincker/theauth-go/v2/internal/saml/handlers"
	scimhandlers "github.com/glincker/theauth-go/v2/internal/scim/handlers"
	"github.com/go-chi/chi/v5"
)

// mounts.go: thin forwarder around the extracted
// internal/admin/handlers package. PR F architecture reorg
// (2026-06-20) moved the 12 /admin/v1 endpoints plus the
// requireOrgMatch middleware there. The agent + delegation admin
// subtree (PR F's other extraction at internal/agent/handlers) is
// wired in via the MountAgents callback supplied below.

// adminRBACAdapter implements adminhandlers.RBACService on top of
// root *TheAuth.
type adminRBACAdapter struct{ a *TheAuth }

func (s adminRBACAdapter) GrantRole(ctx context.Context, actorID, userID, roleID models.ULID) error {
	return s.a.GrantRole(ctx, actorID, userID, roleID)
}

func (s adminRBACAdapter) RevokeRole(ctx context.Context, actorID, userID, roleID models.ULID) error {
	return s.a.RevokeRole(ctx, actorID, userID, roleID)
}

func (s adminRBACAdapter) CreateRole(ctx context.Context, orgID models.ULID, name, description string, permissions []string) (models.Role, error) {
	return s.a.CreateRole(ctx, orgID, name, description, permissions)
}

func (s adminRBACAdapter) UpdateRole(ctx context.Context, roleID models.ULID, name, description string, permissions []string) (models.Role, error) {
	return s.a.UpdateRole(ctx, roleID, name, description, permissions)
}

func (s adminRBACAdapter) DeleteRole(ctx context.Context, roleID models.ULID) error {
	return s.a.DeleteRole(ctx, roleID)
}

// adminAuditAdapter implements adminhandlers.AuditService on top of
// root *TheAuth.
type adminAuditAdapter struct{ a *TheAuth }

func (s adminAuditAdapter) QueryAudit(ctx context.Context, q models.AuditQuery) ([]models.AuditEvent, string, error) {
	return s.a.QueryAudit(ctx, q)
}

func (s adminAuditAdapter) EmitAudit(ctx context.Context, action string, target models.TargetRef, meta map[string]any) {
	s.a.EmitAudit(ctx, action, target, meta)
}

func (s adminAuditAdapter) HashEmailForAudit(email string) string {
	return HashEmailForAudit(email)
}

// mountAdmin wires the /admin/v1 routes via the extracted
// internal/admin/handlers package. Called from Mount when
// Config.Admin is non-nil.
func (a *TheAuth) mountAdmin(r chi.Router) {
	pathPrefix := ""
	if a.adminCfg != nil {
		pathPrefix = a.adminCfg.PathPrefix
	}
	h := adminhandlers.New(
		adminSessionStorage{Storage: a.storage, mgmt: a.sx.mgmt},
		adminRBACAdapter{a: a},
		adminAuditAdapter{a: a},
		pathPrefix,
		userFromRequest,
		sessionFromRequest,
	)
	h.Mount(
		r,
		a.RequireAuth(),
		func(permission string) func(http.Handler) http.Handler {
			return a.RequirePermission(permission)
		},
		func(r chi.Router) {
			a.mountAdminAgents(r)
			a.mountAdminRegistrationTokens(r)
		},
	)
}

// handlers_admin_agents.go: thin forwarder around the extracted
// internal/agent/handlers package. PR F architecture reorg
// (2026-06-20) moved the seven /admin/v1/.../{agents,delegations}
// endpoints there.

// adminAgentAdapter implements agenthandlers.AgentService on top of
// root *TheAuth.
type adminAgentAdapter struct{ a *TheAuth }

func (s adminAgentAdapter) ListAgentsByOwner(ctx context.Context, owner models.AgentOwner) ([]models.Agent, error) {
	return s.a.ListAgentsByOwner(ctx, owner)
}

func (s adminAgentAdapter) CreateAgent(ctx context.Context, in models.CreateAgentInput) (models.Agent, models.AgentSecret, error) {
	return s.a.CreateAgent(ctx, in)
}

func (s adminAgentAdapter) AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error) {
	return s.a.agentSvc.AgentByID(ctx, id)
}

func (s adminAgentAdapter) GetAgent(ctx context.Context, id models.ULID) (*models.Agent, error) {
	return s.a.GetAgent(ctx, id)
}

func (s adminAgentAdapter) SuspendAgent(ctx context.Context, agentID models.ULID, reason string) error {
	return s.a.SuspendAgent(ctx, agentID, reason)
}

func (s adminAgentAdapter) ResumeAgent(ctx context.Context, agentID models.ULID) error {
	return s.a.ResumeAgent(ctx, agentID)
}

func (s adminAgentAdapter) RevokeAgent(ctx context.Context, agentID models.ULID, reason string) error {
	return s.a.RevokeAgent(ctx, agentID, reason)
}

// adminDelegationAdapter implements
// agenthandlers.DelegationService on top of root *TheAuth.
type adminDelegationAdapter struct{ a *TheAuth }

func (s adminDelegationAdapter) ListDelegationsForUser(ctx context.Context, userID models.ULID) ([]models.DelegationGrant, error) {
	return s.a.ListDelegationsForUser(ctx, userID)
}

func (s adminDelegationAdapter) ListDelegationsForAgent(ctx context.Context, agentID models.ULID) ([]models.DelegationGrant, error) {
	return s.a.ListDelegationsForAgent(ctx, agentID)
}

func (s adminDelegationAdapter) GrantDelegation(ctx context.Context, in models.GrantDelegationInput) (models.DelegationGrant, error) {
	return s.a.GrantDelegation(ctx, in)
}

func (s adminDelegationAdapter) GrantByID(ctx context.Context, grantID models.ULID) (*models.DelegationGrant, error) {
	return s.a.delegationSvc.GrantByID(ctx, grantID)
}

func (s adminDelegationAdapter) RevokeDelegation(ctx context.Context, grantID models.ULID, reason string) error {
	return s.a.RevokeDelegation(ctx, grantID, reason)
}

// adminOrgAdapter implements agenthandlers.OrganizationLookup on top
// of the root storage.
type adminOrgAdapter struct{ a *TheAuth }

func (s adminOrgAdapter) OrganizationMemberRole(ctx context.Context, orgID, userID models.ULID) (string, error) {
	return s.a.storage.OrganizationMemberRole(ctx, orgID, userID)
}

// mountAdminRegistrationTokens wires the initial access token routes under the
// org-scoped admin tree when the AS is on and the storage can hold them.
func (a *TheAuth) mountAdminRegistrationTokens(r chi.Router) {
	if a.as == nil {
		return
	}
	ashandlers.NewAdmin(a.as, userFromRequest).Mount(r, func(permission string) func(http.Handler) http.Handler {
		return a.RequirePermission(permission)
	})
}

// mountAdminAgents wires the agent + delegation routes via the
// extracted internal/agent/handlers package. Called from mountAdmin
// when the agent identity service is configured.
func (a *TheAuth) mountAdminAgents(r chi.Router) {
	if a.agentCfg == nil || a.as == nil {
		return
	}
	h := agenthandlers.New(
		adminAgentAdapter{a: a},
		adminDelegationAdapter{a: a},
		adminOrgAdapter{a: a},
	)
	h.Mount(r, func(permission string) func(http.Handler) http.Handler {
		return a.RequirePermission(permission)
	})
}

// adminSessionStorage layers the optional session list onto the full Storage,
// which assembled storages would otherwise hide from a type assertion.
type adminSessionStorage struct {
	Storage
	mgmt SessionManagementStorage
}

// ListUserSessions returns the user's live sessions, or nil when the storage
// has no SessionManagementStorage.
func (s adminSessionStorage) ListUserSessions(ctx context.Context, userID models.ULID) ([]models.Session, error) {
	if s.mgmt == nil {
		return nil, nil
	}
	return s.mgmt.ListUserSessions(ctx, userID)
}

// ---------- /account end-user self-service ----------

// handlers_account.go: thin forwarder around the extracted
// internal/account/handlers package. PR F architecture reorg
// (2026-06-20) moved the six /account/* end-user self-service
// endpoints there; this file keeps the mountAccount entrypoint and
// the two small adapters that bridge the *TheAuth surface to the
// handler-side service interfaces.

// accountAgentAdapter implements accounthandlers.AgentService on top
// of root *TheAuth. AgentByID forwards to the agentSvc field directly
// because the public *TheAuth surface does not expose an AgentByID
// method (only the wider GetAgent, which the handler uses on the
// admin path).
type accountAgentAdapter struct{ a *TheAuth }

func (s accountAgentAdapter) ListAgentsByOwner(ctx context.Context, owner models.AgentOwner) ([]models.Agent, error) {
	return s.a.ListAgentsByOwner(ctx, owner)
}

func (s accountAgentAdapter) CreateAgent(ctx context.Context, in models.CreateAgentInput) (models.Agent, models.AgentSecret, error) {
	return s.a.CreateAgent(ctx, in)
}

func (s accountAgentAdapter) AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error) {
	return s.a.agentSvc.AgentByID(ctx, id)
}

func (s accountAgentAdapter) RevokeAgent(ctx context.Context, agentID models.ULID, reason string) error {
	return s.a.RevokeAgent(ctx, agentID, reason)
}

// accountDelegationAdapter implements
// accounthandlers.DelegationService on top of root *TheAuth.
type accountDelegationAdapter struct{ a *TheAuth }

func (s accountDelegationAdapter) ListDelegationsForUser(ctx context.Context, userID models.ULID) ([]models.DelegationGrant, error) {
	return s.a.ListDelegationsForUser(ctx, userID)
}

func (s accountDelegationAdapter) GrantDelegation(ctx context.Context, in models.GrantDelegationInput) (models.DelegationGrant, error) {
	return s.a.GrantDelegation(ctx, in)
}

func (s accountDelegationAdapter) GrantByID(ctx context.Context, grantID models.ULID) (*models.DelegationGrant, error) {
	return s.a.delegationSvc.GrantByID(ctx, grantID)
}

func (s accountDelegationAdapter) RevokeDelegation(ctx context.Context, grantID models.ULID, reason string) error {
	return s.a.RevokeDelegation(ctx, grantID, reason)
}

// accountIdentityLinkAdapter wraps *TheAuth to satisfy the
// accounthandlers.IdentityLinkService interface without importing root from
// an internal package.
type accountIdentityLinkAdapter struct{ a *TheAuth }

func (s accountIdentityLinkAdapter) LinkOAuthToCurrentUser(
	ctx context.Context,
	sessionToken, providerName, providerUserID string,
	accessTokenEnc, refreshTokenEnc []byte,
	expiresAt *time.Time,
	scope string,
) error {
	return s.a.identityLinkSvc.LinkOAuthToCurrentUser(
		ctx, sessionToken, providerName, providerUserID,
		accessTokenEnc, refreshTokenEnc, expiresAt, scope,
	)
}

func (s accountIdentityLinkAdapter) LinkPasswordToCurrentUser(ctx context.Context, sessionToken, password string) error {
	return s.a.identityLinkSvc.LinkPasswordToCurrentUser(ctx, sessionToken, password)
}

func (s accountIdentityLinkAdapter) MergeAccounts(ctx context.Context, sessionToken string, secondaryID models.ULID, input identitylink.MergeInput) error {
	return s.a.identityLinkSvc.MergeAccounts(ctx, sessionToken, secondaryID, input)
}

func (s accountIdentityLinkAdapter) UnlinkOAuthProvider(ctx context.Context, sessionToken, provider string) error {
	return s.a.identityLinkSvc.UnlinkOAuthProvider(ctx, sessionToken, provider)
}

// sessionTokenFromRequest extracts the raw session token from the request
// cookie. Passed to the identity-link handler so it can call the service
// methods with the caller's session token.
func (a *TheAuth) sessionTokenFromRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(a.cookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

// mountAccount wires the /account routes via the extracted
// internal/account/handlers package. Idempotent guard matches the
// legacy root: only fires when AccountUX, AgentIdentity, and the AS
// are all configured.
//
// Identity-linking routes (/account/identities/*) are also mounted here
// whenever identityLinkSvc is non-nil (always true after wireServices).
func (a *TheAuth) mountAccount(r chi.Router) {
	if !a.accountUX || a.agentCfg == nil || a.as == nil {
		// Still mount identity-linking routes independently of AccountUX if
		// the service was constructed (which it always is after New).
		if a.identityLinkSvc != nil {
			h := accounthandlers.New(nil, nil, userFromRequest)
			h.WithIdentityLink(
				accountIdentityLinkAdapter{a: a},
				a.sessionTokenFromRequest,
				nil, // OAuthLinkInitiator wired below when providers are configured
			)
			h.Mount(r, a.RequireAuth())
		}
		return
	}
	h := accounthandlers.New(
		accountAgentAdapter{a: a},
		accountDelegationAdapter{a: a},
		userFromRequest,
	)
	if a.identityLinkSvc != nil {
		h.WithIdentityLink(
			accountIdentityLinkAdapter{a: a},
			a.sessionTokenFromRequest,
			nil, // OAuthLinkInitiator: wired when a separate PR adds OAuth link flow support
		)
	}
	h.Mount(r, a.RequireAuth())
}

// ---------- /auth/orgs multi-tenancy ----------

// handlers_organizations.go: thin forwarder around the extracted
// internal/organizations/handlers package. PR F architecture reorg
// (2026-06-20) moved the seven /auth/orgs/* endpoints there. SAML
// connection CRUD and SCIM token CRUD subroutes mount through the
// same /auth/orgs tree via the mountSub callback below; both call
// into their own extracted internal handler packages.

// organizationsServiceAdapter implements orghandlers.Service on top of
// the root *TheAuth, forwarding to the existing public methods so the
// extracted package does not import root.
type organizationsServiceAdapter struct{ a *TheAuth }

func (s organizationsServiceAdapter) Create(ctx context.Context, name, slug string, ownerUserID ULID) (Organization, error) {
	return s.a.CreateOrganization(ctx, name, slug, ownerUserID)
}

func (s organizationsServiceAdapter) ByID(ctx context.Context, id ULID) (*Organization, error) {
	return s.a.OrganizationByID(ctx, id)
}

func (s organizationsServiceAdapter) AddMember(ctx context.Context, orgID, userID ULID, role string) error {
	return s.a.AddOrganizationMember(ctx, orgID, userID, role)
}

func (s organizationsServiceAdapter) RemoveMember(ctx context.Context, orgID, userID ULID) error {
	return s.a.RemoveOrganizationMember(ctx, orgID, userID)
}

func (s organizationsServiceAdapter) ListUserOrganizations(ctx context.Context, userID ULID) ([]Organization, error) {
	return s.a.ListUserOrganizations(ctx, userID)
}

func (s organizationsServiceAdapter) SetActive(ctx context.Context, sessionID ULID, orgID *ULID) error {
	return s.a.SetActiveOrganization(ctx, sessionID, orgID)
}

// mountOrganizations wires the /auth/orgs routes via the extracted
// internal/organizations/handlers package. Only called by Mount when
// Config.Organizations is non-nil. SAML connection CRUD and SCIM token
// CRUD subroutes are mounted via the mountSub callback so their root
// handlers (which still depend on root-only services) share the same
// chi tree.
func (a *TheAuth) mountOrganizations(r chi.Router) {
	h := orghandlers.New(
		organizationsServiceAdapter{a: a},
		a.requireOrgRoleHTTP,
		userFromRequest,
		sessionFromRequest,
	)
	requireAuth := a.RequireAuth()
	mountSub := func(r chi.Router) {
		if a.samlCfg != nil {
			r.Route("/{orgId}/saml/connections", func(r chi.Router) {
				r.Use(requireAuth)
				a.mountSAMLConnectionCRUD(r)
			})
		}
		if a.scimCfg != nil {
			r.Route("/{orgId}/scim/tokens", func(r chi.Router) {
				r.Use(requireAuth)
				a.mountSCIMTokenCRUD(r)
			})
		}
	}
	h.Mount(r, requireAuth, mountSub)
}

// requireOrgRoleHTTP adapts the *TheAuth role-check helper to the
// signature the extracted handler package expects. The body forwards
// to the legacy root requireOrgRole verbatim.
func (a *TheAuth) requireOrgRoleHTTP(w http.ResponseWriter, r *http.Request, orgID, userID ULID, roles ...string) bool {
	return a.requireOrgRole(w, r, orgID, userID, roles...)
}

// userFromRequest is the context shim handed to extracted handler
// packages so they can pull the authenticated user without importing
// the root ctxKey type.
func userFromRequest(r *http.Request) (*models.User, bool) {
	return UserFromContext(r.Context())
}

// sessionFromRequest mirrors userFromRequest for the session.
func sessionFromRequest(r *http.Request) (*models.Session, bool) {
	return SessionFromContext(r.Context())
}

// requireOrgRole retains the legacy signature used by handlers still
// owning their own logic in root (SAML connection CRUD, SCIM token
// CRUD). When those handlers move into their own packages, the helper
// goes with them.
func (a *TheAuth) requireOrgRole(w http.ResponseWriter, r *http.Request, orgID, userID ULID, roles ...string) bool {
	role, err := a.storage.OrganizationMemberRole(r.Context(), orgID, userID)
	if err != nil {
		httpx.Error(w, http.StatusNotFound, "not found")
		return false
	}
	for _, want := range roles {
		if role == want {
			return true
		}
	}
	httpx.Error(w, http.StatusForbidden, "forbidden")
	return false
}

// ---------- SAML SP-flow + connection CRUD ----------

// handlers_saml.go: thin forwarders around the extracted
// internal/saml/handlers package. PR E moved the SP-flow endpoints
// (/auth/saml/{connectionId}/{login,acs,metadata}) there; PR F moved
// the per-organization connection CRUD endpoints into the same
// package (crud.go) so root no longer owns any SAML handler bodies.

// samlServiceAdapter implements internal/saml/handlers.Service on top
// of the root *TheAuth, exposing the three SP-flow methods the
// extracted handler needs (BeginLogin, FinishLogin, MetadataXML).
// FinishLogin discards the second return (Session) because the
// handler only writes the cookie.
type samlServiceAdapter struct{ a *TheAuth }

func (s samlServiceAdapter) BeginLogin(ctx context.Context, id models.ULID, relayState string) (string, error) {
	return s.a.BeginSAMLLogin(ctx, id, relayState)
}

func (s samlServiceAdapter) FinishLogin(ctx context.Context, id models.ULID, samlResp, ua, ip string) (string, error) {
	tok, _, err := s.a.FinishSAMLLogin(ctx, id, samlResp, ua, ip)
	return tok, err
}

func (s samlServiceAdapter) MetadataXML(ctx context.Context, id models.ULID) ([]byte, error) {
	return s.a.SAMLMetadataXML(ctx, id)
}

// samlConnectionServiceAdapter implements
// internal/saml/handlers.ConnectionService on top of the root
// *TheAuth, projecting the handler-side input type into the root
// SAMLConnectionInput so the extracted package does not import root.
type samlConnectionServiceAdapter struct{ a *TheAuth }

func (s samlConnectionServiceAdapter) Create(ctx context.Context, in samlhandlers.SAMLConnectionInput) (models.SAMLConnection, error) {
	return s.a.CreateSAMLConnection(ctx, samlConnectionFromHandlers(in))
}

func (s samlConnectionServiceAdapter) Update(ctx context.Context, id models.ULID, in samlhandlers.SAMLConnectionInput) (models.SAMLConnection, error) {
	return s.a.UpdateSAMLConnection(ctx, id, samlConnectionFromHandlers(in))
}

func (s samlConnectionServiceAdapter) Delete(ctx context.Context, id models.ULID) error {
	return s.a.DeleteSAMLConnection(ctx, id)
}

func (s samlConnectionServiceAdapter) ByID(ctx context.Context, id models.ULID) (*models.SAMLConnection, error) {
	return s.a.SAMLConnectionByID(ctx, id)
}

func (s samlConnectionServiceAdapter) List(ctx context.Context, orgID models.ULID) ([]models.SAMLConnection, error) {
	return s.a.ListSAMLConnections(ctx, orgID)
}

func samlConnectionFromHandlers(in samlhandlers.SAMLConnectionInput) SAMLConnectionInput {
	return SAMLConnectionInput{
		OrganizationID: in.OrganizationID,
		IdPEntityID:    in.IdPEntityID,
		IdPSSOURL:      in.IdPSSOURL,
		IdPX509Cert:    in.IdPX509Cert,
		SPEntityID:     in.SPEntityID,
		SPACSURL:       in.SPACSURL,
		AttributeMap:   in.AttributeMap,
	}
}

// newSAMLHandler builds the extracted Handler with both the SP-flow
// and the CRUD-side dependencies attached. Used by both mountSAML
// (SP-flow) and the org-tree subroute (CRUD).
func (a *TheAuth) newSAMLHandler() *samlhandlers.Handler {
	h := samlhandlers.New(
		samlServiceAdapter{a: a},
		samlhandlers.SessionCookieConfig{
			Name:       a.cookieName,
			SecureFlag: a.secureCookie,
			TTL:        a.sessionTTL,
		},
		a.postLoginRedirect,
	)
	if a.samlCfg != nil {
		h.SetAllowedRelayStates(a.samlCfg.AllowedRelayStates)
	}
	h.AttachCRUD(samlConnectionServiceAdapter{a: a}, a.requireOrgRoleHTTP, userFromRequest)
	return h
}

// mountSAML wires the public-facing SAML SP-flow endpoints (login,
// ACS, metadata) via the extracted internal/saml/handlers package.
func (a *TheAuth) mountSAML(r chi.Router) {
	a.newSAMLHandler().Mount(r)
}

// mountSAMLConnectionCRUD mounts the five per-org connection CRUD
// endpoints. Called from mountOrganizations' mountSub callback when
// Config.SAML is non-nil so the route still resolves under
// /auth/orgs/{orgId}/saml/connections.
func (a *TheAuth) mountSAMLConnectionCRUD(r chi.Router) {
	a.newSAMLHandler().MountCRUD(r)
}

// ---------- SCIM 2.0 resource + token CRUD ----------

// handlers_scim.go: thin forwarder around the extracted
// internal/scim/handlers package. PR F architecture reorg
// (2026-06-20) moved the 15 SCIM resource endpoints and the 3 token
// CRUD endpoints out of root; the wire helpers and PATCH logic now
// live in internal/scim (wire.go, patch.go). Root keeps a tiny
// service adapter, the audit-emit shim, and a constructor that wires
// everything onto chi via mountSCIM (called by Mount) and
// mountSCIMTokenCRUD (called from mountOrganizations' mountSub).

// scimTokenServiceAdapter implements scimhandlers.TokenService on top
// of the root *TheAuth. The adapter exists so the extracted package
// does not import root.
type scimTokenServiceAdapter struct{ a *TheAuth }

func (s scimTokenServiceAdapter) CreateToken(ctx context.Context, orgID models.ULID, name string) (string, models.SCIMToken, error) {
	return s.a.CreateSCIMToken(ctx, orgID, name)
}

func (s scimTokenServiceAdapter) RevokeToken(ctx context.Context, id models.ULID) error {
	return s.a.RevokeSCIMToken(ctx, id)
}

func (s scimTokenServiceAdapter) ListTokens(ctx context.Context, orgID models.ULID) ([]models.SCIMToken, error) {
	return s.a.ListSCIMTokens(ctx, orgID)
}

// newSCIMHandler builds the extracted Handler with both the resource
// and token-CRUD-side dependencies wired.
func (a *TheAuth) newSCIMHandler() *scimhandlers.Handler {
	maxPage := 0
	if a.scimCfg != nil {
		maxPage = a.scimCfg.MaxPageSize
	}
	return scimhandlers.New(
		a.storage,
		scimTokenServiceAdapter{a: a},
		scimhandlers.Config{
			BaseURL:     a.baseURL,
			MaxPageSize: maxPage,
			Email:       a.emailNorm,
		},
		a.emitSCIMAuditExternal,
		a.ensureOrgMembership,
		a.requireOrgRoleHTTP,
		userFromRequest,
		scimOrgFromContext,
		scimTokenIDFromContext,
	)
}

// mountSCIM wires the /scim/v2/* resource and discovery endpoints via
// the extracted handler. The scimAuth middleware stays on root because
// it owns the SCIMConfig.RequireHTTPS state and the token lookup;
// passing it in keeps the import direction one-way.
func (a *TheAuth) mountSCIM(r chi.Router) {
	a.newSCIMHandler().Mount(r, a.scimAuth())
}

// mountSCIMTokenCRUD mounts the three /auth/orgs/{orgId}/scim/tokens
// endpoints. Called from mountOrganizations' mountSub callback when
// Config.SCIM is non-nil so the route still resolves under the org
// tree.
func (a *TheAuth) mountSCIMTokenCRUD(r chi.Router) {
	a.newSCIMHandler().MountTokenCRUD(r)
}

// emitSCIMAuditExternal adapts the in-package emitSCIMAudit signature
// to the AuditEmitter callback shape the extracted handler expects:
// it attaches the organization to the audit metadata, sets the
// SCIM-token actor, and forwards to the existing async writer.
func (a *TheAuth) emitSCIMAuditExternal(ctx context.Context, action string, orgID, resourceID, scimTokenID models.ULID, detail string) {
	md := AuditMetadata{OrganizationID: &orgID}
	ctx = WithAuditMetadata(ctx, md)
	meta := map[string]any{"scim_token_id": scimTokenID.String()}
	if detail != "" {
		meta["detail"] = detail
	}
	a.EmitAudit(ctx, action, TargetRef{Type: "user", ID: resourceID.String()}, meta)
}
