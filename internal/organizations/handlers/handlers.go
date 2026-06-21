// Package handlers exposes the /auth/orgs/* HTTP endpoints for
// multi-tenant organization create / read / membership management.
//
// Extracted from root handlers_organizations.go in PR F of the 2026-06
// architecture reorg. The root *theauth.TheAuth constructs a Handler
// here and Mount is invoked from a thin mountOrganizationsHandlers
// forwarder so the public surface and route shapes are unchanged.
//
// Sub-route mounting for SAML connection CRUD and SCIM token CRUD
// stays in root because those CRUDs depend on services this handler
// does not own; the root forwarder wires those subroutes after this
// Handler's Mount returns by walking the same chi router.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/glincker/theauth-go/internal/httpx"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"
)

// Service is the minimum organization surface the handler needs.
// Implemented by root *TheAuth via an adapter so this package does not
// import root.
type Service interface {
	Create(ctx context.Context, name, slug string, ownerUserID models.ULID) (models.Organization, error)
	ByID(ctx context.Context, id models.ULID) (*models.Organization, error)
	AddMember(ctx context.Context, orgID, userID models.ULID, role string) error
	RemoveMember(ctx context.Context, orgID, userID models.ULID) error
	ListUserOrganizations(ctx context.Context, userID models.ULID) ([]models.Organization, error)
	SetActive(ctx context.Context, sessionID models.ULID, orgID *models.ULID) error
}

// RoleChecker is a context-aware role-membership predicate. Returns
// true when the user holds at least one of the supplied roles inside
// the organization. The implementation owns the HTTP error response on
// failure (writes 403 / 404 + returns false) so the handler signature
// matches the legacy root requireOrgRole exactly.
type RoleChecker func(w http.ResponseWriter, r *http.Request, orgID, userID models.ULID, roles ...string) bool

// UserFromCtx pulls the authenticated *models.User out of the request
// context. Supplied by root so this package does not need to import the
// root ctxKey type.
type UserFromCtx func(r *http.Request) (*models.User, bool)

// SessionFromCtx pulls the authenticated *models.Session out of the
// request context. Same rationale as UserFromCtx.
type SessionFromCtx func(r *http.Request) (*models.Session, bool)

// Handler owns the seven /auth/orgs/* endpoints.
type Handler struct {
	svc         Service
	requireRole RoleChecker
	userFromCtx UserFromCtx
	sessFromCtx SessionFromCtx
}

// New constructs a Handler with all of its callable dependencies.
func New(svc Service, requireRole RoleChecker, userFromCtx UserFromCtx, sessFromCtx SessionFromCtx) *Handler {
	return &Handler{
		svc:         svc,
		requireRole: requireRole,
		userFromCtx: userFromCtx,
		sessFromCtx: sessFromCtx,
	}
}

// RequireRole exposes the constructor-supplied RoleChecker so the root
// forwarder can re-use it for SAML and SCIM CRUD subroutes mounted on
// the same /auth/orgs tree.
func (h *Handler) RequireRole() RoleChecker { return h.requireRole }

// Mount registers /orgs/* under r. requireAuth wraps every endpoint
// (matches the legacy root which called .With(a.RequireAuth()) on each
// route). The caller is expected to mount subroute trees (SAML
// connections, SCIM tokens) after Mount returns, using the same chi
// router and any additional handlers the root owns.
func (h *Handler) Mount(r chi.Router, requireAuth func(http.Handler) http.Handler, mountSub func(r chi.Router)) {
	r.Route("/orgs", func(r chi.Router) {
		r.With(requireAuth).Post("/", h.handleCreate)
		r.With(requireAuth).Get("/", h.handleList)
		r.With(requireAuth).Get("/{id}", h.handleGet)
		r.With(requireAuth).Post("/{id}/members", h.handleAddMember)
		r.With(requireAuth).Delete("/{id}/members/{userId}", h.handleRemoveMember)
		r.With(requireAuth).Post("/{id}/activate", h.handleActivate)
		r.With(requireAuth).Post("/clear-active", h.handleClearActive)
		if mountSub != nil {
			mountSub(r)
		}
	})
}

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	org, err := h.svc.Create(r.Context(), body.Name, body.Slug, user.ID)
	if err != nil {
		if errors.Is(err, models.ErrSlugTaken) {
			http.Error(w, "slug already taken", http.StatusConflict)
			return
		}
		http.Error(w, "invalid organization", http.StatusBadRequest)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, org)
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	orgs, err := h.svc.ListUserOrganizations(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, orgs)
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	id, ok := httpx.PathULID(w, r, "id")
	if !ok || user == nil {
		return
	}
	if !h.requireRole(w, r, id, user.ID, models.OrgRoleMember, models.OrgRoleAdmin, models.OrgRoleOwner) {
		return
	}
	org, err := h.svc.ByID(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, org)
}

func (h *Handler) handleAddMember(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	id, ok := httpx.PathULID(w, r, "id")
	if !ok || user == nil {
		return
	}
	if !h.requireRole(w, r, id, user.ID, models.OrgRoleAdmin, models.OrgRoleOwner) {
		return
	}
	var body struct {
		UserID string `json:"userId"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	uid, err := ulid.Parse(body.UserID)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	if err := h.svc.AddMember(r.Context(), id, uid, body.Role); err != nil {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	id, ok := httpx.PathULID(w, r, "id")
	uid, ok2 := httpx.PathULID(w, r, "userId")
	if !ok || !ok2 || user == nil {
		return
	}
	if !h.requireRole(w, r, id, user.ID, models.OrgRoleOwner) {
		return
	}
	if err := h.svc.RemoveMember(r.Context(), id, uid); err != nil {
		if errors.Is(err, models.ErrLastOwner) {
			http.Error(w, "cannot remove the last owner", http.StatusConflict)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleActivate(w http.ResponseWriter, r *http.Request) {
	sess, _ := h.sessFromCtx(r)
	user, _ := h.userFromCtx(r)
	id, ok := httpx.PathULID(w, r, "id")
	if !ok || sess == nil || user == nil {
		return
	}
	if !h.requireRole(w, r, id, user.ID, models.OrgRoleMember, models.OrgRoleAdmin, models.OrgRoleOwner) {
		return
	}
	orgID := id
	if err := h.svc.SetActive(r.Context(), sess.ID, &orgID); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleClearActive(w http.ResponseWriter, r *http.Request) {
	sess, _ := h.sessFromCtx(r)
	if sess == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.svc.SetActive(r.Context(), sess.ID, nil); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
