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

// mounts.go wires the admin and agent admin routes through the extracted internal/admin and
// internal/agent handler packages.

// adminRBACAdapter adapts root *TheAuth to adminhandlers.RBACService.
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

// adminAuditAdapter adapts root *TheAuth to adminhandlers.AuditService.
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

// adminLifecycleAdapter adapts root *TheAuth to adminhandlers.Lifecycle.
type adminLifecycleAdapter struct{ a *TheAuth }

func (s adminLifecycleAdapter) SetMustChangePassword(ctx context.Context, userID models.ULID, required bool) error {
	return s.a.SetMustChangePassword(ctx, userID, required)
}

func (s adminLifecycleAdapter) DisableUser(ctx context.Context, userID models.ULID) error {
	return s.a.DisableUser(ctx, userID)
}

func (s adminLifecycleAdapter) EnableUser(ctx context.Context, userID models.ULID) error {
	return s.a.EnableUser(ctx, userID)
}

func (s adminLifecycleAdapter) DeleteUser(ctx context.Context, userID models.ULID) error {
	return s.a.DeleteUser(ctx, userID)
}

// mountAdmin wires the /admin/v1 routes. It is called from Mount when Config.Admin is set.
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
	h.WithLifecycle(adminLifecycleAdapter{a: a})
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

// The agent and delegation admin endpoints are wired through the MountAgents callback above.

// adminAgentAdapter adapts root *TheAuth to agenthandlers.AgentService.
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

// adminDelegationAdapter adapts root *TheAuth to agenthandlers.DelegationService.
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

// adminOrgAdapter implements agenthandlers.OrganizationLookup over the root storage.
type adminOrgAdapter struct{ a *TheAuth }

func (s adminOrgAdapter) OrganizationMemberRole(ctx context.Context, orgID, userID models.ULID) (string, error) {
	return s.a.storage.OrganizationMemberRole(ctx, orgID, userID)
}

// mountAdminRegistrationTokens wires initial access token routes under the org-scoped admin tree
// when the AS is on and storage can hold them.
func (a *TheAuth) mountAdminRegistrationTokens(r chi.Router) {
	if a.as == nil {
		return
	}
	ashandlers.NewAdmin(a.as, userFromRequest).Mount(r, func(permission string) func(http.Handler) http.Handler {
		return a.RequirePermission(permission)
	})
}

// mountAdminAgents wires the agent and delegation routes. It runs from mountAdmin when agent
// identity is configured.
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

// adminSessionStorage adds the optional session list to the full Storage, which assembled storages
// would hide from a type assertion.
type adminSessionStorage struct {
	Storage
	mgmt SessionManagementStorage
}

// ListUserSessions returns the user's live sessions, or nil when storage lacks SessionManagementStorage.
func (s adminSessionStorage) ListUserSessions(ctx context.Context, userID models.ULID) ([]models.Session, error) {
	if s.mgmt == nil {
		return nil, nil
	}
	return s.mgmt.ListUserSessions(ctx, userID)
}

// accountAgentAdapter implements accounthandlers.AgentService. AgentByID reads agentSvc directly
// because the public surface only exposes GetAgent.
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

// accountDelegationAdapter implements accounthandlers.DelegationService over root *TheAuth.
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

// accountIdentityLinkAdapter satisfies accounthandlers.IdentityLinkService without importing root
// from an internal package.
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

// sessionTokenFromRequest returns the raw session token from the cookie, for identity-link handlers.
func (a *TheAuth) sessionTokenFromRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(a.cookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

// mountAccount wires the /account routes. It mounts only when AccountUX, AgentIdentity and the AS
// are all configured. Identity-linking routes mount whenever identityLinkSvc is set.
func (a *TheAuth) mountAccount(r chi.Router) {
	if !a.accountUX || a.agentCfg == nil || a.as == nil {
		if a.identityLinkSvc != nil {
			h := accounthandlers.New(nil, nil, userFromRequest)
			a.withSelfDelete(h)
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
	a.withSelfDelete(h)
	if a.identityLinkSvc != nil {
		h.WithIdentityLink(
			accountIdentityLinkAdapter{a: a},
			a.sessionTokenFromRequest,
			nil, // OAuthLinkInitiator: wired when a separate PR adds OAuth link flow support
		)
	}
	h.Mount(r, a.RequireAuth())
}

// organizationsServiceAdapter implements orghandlers.Service over root *TheAuth so the extracted
// package does not import root.
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

// mountOrganizations wires the /auth/orgs routes. It runs only when Config.Organizations is set.
// SAML and SCIM token subroutes mount through the mountSub callback so they share the same chi
// tree.
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

// requireOrgRoleHTTP adapts the root requireOrgRole helper to the signature the extracted handler
// package expects.
func (a *TheAuth) requireOrgRoleHTTP(w http.ResponseWriter, r *http.Request, orgID, userID ULID, roles ...string) bool {
	return a.requireOrgRole(w, r, orgID, userID, roles...)
}

// userFromRequest hands the authenticated user to extracted handler packages without importing the
// root ctxKey type.
func userFromRequest(r *http.Request) (*models.User, bool) {
	return UserFromContext(r.Context())
}

// sessionFromRequest mirrors userFromRequest for the session.
func sessionFromRequest(r *http.Request) (*models.Session, bool) {
	return SessionFromContext(r.Context())
}

// requireOrgRole is the legacy helper still used by root-owned handlers.
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

// samlServiceAdapter implements the SP-flow service of internal/saml/handlers. FinishLogin drops
// the Session return because the handler only writes the cookie.
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

// samlConnectionServiceAdapter projects handler-side input onto SAMLConnectionInput so the
// extracted package does not import root.
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

// newSAMLHandler builds the extracted SAML handler with SP-flow and CRUD dependencies.
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

// mountSAML wires the public SAML SP-flow endpoints (login, ACS, metadata).
func (a *TheAuth) mountSAML(r chi.Router) {
	a.newSAMLHandler().Mount(r)
}

// mountSAMLConnectionCRUD mounts the per-org connection CRUD endpoints under
// /auth/orgs/{orgId}/saml/connections.
func (a *TheAuth) mountSAMLConnectionCRUD(r chi.Router) {
	a.newSAMLHandler().MountCRUD(r)
}

// scimTokenServiceAdapter implements scimhandlers.TokenService over root *TheAuth.
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

// newSCIMHandler builds the extracted SCIM handler with resource and token dependencies.
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

// mountSCIM wires the /scim/v2 endpoints. The auth middleware stays in root because it owns
// RequireHTTPS and token lookup.
func (a *TheAuth) mountSCIM(r chi.Router) {
	a.newSCIMHandler().Mount(r, a.scimAuth())
}

// mountSCIMTokenCRUD mounts the org-scoped SCIM token endpoints. It runs from the mountSub callback
// when Config.SCIM is set.
func (a *TheAuth) mountSCIMTokenCRUD(r chi.Router) {
	a.newSCIMHandler().MountTokenCRUD(r)
}

// emitSCIMAuditExternal adapts emitSCIMAudit to the AuditEmitter callback shape the extracted
// handler expects.
func (a *TheAuth) emitSCIMAuditExternal(ctx context.Context, action string, orgID, resourceID, scimTokenID models.ULID, detail string) {
	md := AuditMetadata{OrganizationID: &orgID}
	ctx = WithAuditMetadata(ctx, md)
	meta := map[string]any{"scim_token_id": scimTokenID.String()}
	if detail != "" {
		meta["detail"] = detail
	}
	a.EmitAudit(ctx, action, TargetRef{Type: "user", ID: resourceID.String()}, meta)
}
