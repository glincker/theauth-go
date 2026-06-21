package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/glincker/theauth-go/internal/httpx"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/go-chi/chi/v5"
)

// crud.go: per-organization SAML connection CRUD endpoints, mounted
// under /auth/orgs/{orgId}/saml/connections. Extracted from root
// handlers_saml.go in PR F of the 2026-06 architecture reorg. The
// SP-flow endpoints in handlers.go and the CRUD endpoints here share
// the same internal/saml/handlers.Handler value: CRUD methods read
// connectionSvc + roleCheck supplied by NewWithCRUD; SP-flow methods
// read svc + sessionCookie.

// SAMLConnectionInput is the consumer-facing payload for create /
// update. Mirrors models.SAMLAttributeMap-typed AttributeMap so the
// extracted handler does not need to re-declare the wire shape.
type SAMLConnectionInput struct {
	OrganizationID models.ULID
	IdPEntityID    string
	IdPSSOURL      string
	IdPX509Cert    string
	SPEntityID     string
	SPACSURL       string
	AttributeMap   models.SAMLAttributeMap
}

// ConnectionService is the minimum CRUD surface this handler needs.
// Implemented by root *TheAuth so the extracted package does not
// import root.
type ConnectionService interface {
	Create(ctx context.Context, in SAMLConnectionInput) (models.SAMLConnection, error)
	Update(ctx context.Context, id models.ULID, in SAMLConnectionInput) (models.SAMLConnection, error)
	Delete(ctx context.Context, id models.ULID) error
	ByID(ctx context.Context, id models.ULID) (*models.SAMLConnection, error)
	List(ctx context.Context, orgID models.ULID) ([]models.SAMLConnection, error)
}

// RoleChecker is the same predicate the organizations handler exposes;
// CRUD endpoints reject callers who do not hold OrgRoleOwner /
// OrgRoleAdmin in the path organization.
type RoleChecker func(w http.ResponseWriter, r *http.Request, orgID, userID models.ULID, roles ...string) bool

// UserFromCtx pulls the authenticated user from the request context.
type UserFromCtx func(r *http.Request) (*models.User, bool)

// AttachCRUD wires the per-organization SAML connection CRUD services
// onto an existing Handler. Returns the same Handler for chaining.
// Mount must be called once per Handler value; MountCRUD attaches the
// CRUD subroutes onto a chi router scoped under
// /auth/orgs/{orgId}/saml/connections.
func (h *Handler) AttachCRUD(connSvc ConnectionService, roleCheck RoleChecker, userFromCtx UserFromCtx) *Handler {
	h.connSvc = connSvc
	h.roleCheck = roleCheck
	h.userFromCtx = userFromCtx
	return h
}

// MountCRUD registers the five connection CRUD endpoints under r. The
// caller is expected to scope r under /{orgId}/saml/connections and
// wrap requests with the session-auth middleware.
func (h *Handler) MountCRUD(r chi.Router) {
	r.Post("/", h.handleConnectionCreate)
	r.Get("/", h.handleConnectionList)
	r.Get("/{id}", h.handleConnectionGet)
	r.Put("/{id}", h.handleConnectionUpdate)
	r.Delete("/{id}", h.handleConnectionDelete)
}

func (h *Handler) handleConnectionCreate(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	orgID, ok := httpx.PathULID(w, r, "orgId")
	if !ok || user == nil {
		return
	}
	if !h.roleCheck(w, r, orgID, user.ID, models.OrgRoleOwner) {
		return
	}
	var body samlConnectionBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	in := body.toInput(orgID)
	conn, err := h.connSvc.Create(r.Context(), in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, conn)
}

func (h *Handler) handleConnectionList(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	orgID, ok := httpx.PathULID(w, r, "orgId")
	if !ok || user == nil {
		return
	}
	if !h.roleCheck(w, r, orgID, user.ID, models.OrgRoleAdmin, models.OrgRoleOwner) {
		return
	}
	conns, err := h.connSvc.List(r.Context(), orgID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, conns)
}

func (h *Handler) handleConnectionGet(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	orgID, ok := httpx.PathULID(w, r, "orgId")
	id, ok2 := httpx.PathULID(w, r, "id")
	if !ok || !ok2 || user == nil {
		return
	}
	if !h.roleCheck(w, r, orgID, user.ID, models.OrgRoleAdmin, models.OrgRoleOwner) {
		return
	}
	conn, err := h.connSvc.ByID(r.Context(), id)
	if err != nil || conn.OrganizationID != orgID {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, conn)
}

func (h *Handler) handleConnectionUpdate(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	orgID, ok := httpx.PathULID(w, r, "orgId")
	id, ok2 := httpx.PathULID(w, r, "id")
	if !ok || !ok2 || user == nil {
		return
	}
	if !h.roleCheck(w, r, orgID, user.ID, models.OrgRoleOwner) {
		return
	}
	var body samlConnectionBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	in := body.toInput(orgID)
	conn, err := h.connSvc.Update(r.Context(), id, in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, conn)
}

func (h *Handler) handleConnectionDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	orgID, ok := httpx.PathULID(w, r, "orgId")
	id, ok2 := httpx.PathULID(w, r, "id")
	if !ok || !ok2 || user == nil {
		return
	}
	if !h.roleCheck(w, r, orgID, user.ID, models.OrgRoleOwner) {
		return
	}
	if err := h.connSvc.Delete(r.Context(), id); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// samlConnectionBody is the JSON shape consumers POST/PUT. Kept
// internal to the package because it only appears at the HTTP edge;
// the service-layer SAMLConnectionInput above is the cross-package
// contract.
type samlConnectionBody struct {
	IdPEntityID  string                  `json:"idpEntityId"`
	IdPSSOURL    string                  `json:"idpSsoUrl"`
	IdPX509Cert  string                  `json:"idpX509Cert"`
	SPEntityID   string                  `json:"spEntityId"`
	SPACSURL     string                  `json:"spAcsUrl"`
	AttributeMap models.SAMLAttributeMap `json:"attributeMap"`
}

func (b samlConnectionBody) toInput(orgID models.ULID) SAMLConnectionInput {
	return SAMLConnectionInput{
		OrganizationID: orgID,
		IdPEntityID:    b.IdPEntityID,
		IdPSSOURL:      b.IdPSSOURL,
		IdPX509Cert:    b.IdPX509Cert,
		SPEntityID:     b.SPEntityID,
		SPACSURL:       b.SPACSURL,
		AttributeMap:   b.AttributeMap,
	}
}
