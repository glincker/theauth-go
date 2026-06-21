package theauth

import (
	"context"
	"net/http"

	"github.com/glincker/theauth-go/internal/httpx"
	"github.com/glincker/theauth-go/internal/models"
	orghandlers "github.com/glincker/theauth-go/internal/organizations/handlers"
	"github.com/go-chi/chi/v5"
)

// handlers_organizations.go: thin forwarder around the extracted
// internal/organizations/handlers package. PR F architecture reorg
// (2026-06-20) moved the seven /auth/orgs/* endpoints there. The
// shared helpers (pathULID, writeJSON) now forward to internal/httpx;
// root keeps a small forwarder so SAML and SCIM CRUD subroutes (whose
// handlers still live in root for now) can be mounted against the
// same /auth/orgs tree.

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
		http.Error(w, "not found", http.StatusNotFound)
		return false
	}
	for _, want := range roles {
		if role == want {
			return true
		}
	}
	http.Error(w, "forbidden", http.StatusForbidden)
	return false
}

// pathULID is kept in root because handlers_saml.go and handlers_scim.go
// reference it directly. Forwards to httpx.PathULID so the legacy
// surface is preserved without duplicating the helper.
func pathULID(w http.ResponseWriter, r *http.Request, name string) (ULID, bool) {
	return httpx.PathULID(w, r, name)
}

// writeJSON forwards to httpx.WriteJSON for the same reason as
// pathULID above.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	httpx.WriteJSON(w, status, v)
}
