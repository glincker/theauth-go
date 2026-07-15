// Package admin exposes the /admin/v1 organization-scoped admin
// API: user / session / role / audit / oauth-account management.
//
// Extracted from root handlers_admin.go in PR F of the 2026-06
// architecture reorg. Collapsed from internal/admin/handlers into
// internal/admin in PR H (2026-06-22): the handlers/ subdir was the
// only child so the extra nesting added no value. The agent +
// delegation admin routes live in a sibling package
// (internal/agent/handlers) and are mounted as a subtree of the same
// /admin/v1/organizations/{orgID} route via the mountAgents callback
// supplied at Mount time.
package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/admin"
	"github.com/glincker/theauth-go/internal/httpx"
	"github.com/glincker/theauth-go/internal/models"
	internalulid "github.com/glincker/theauth-go/internal/ulid"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"
)

// Storage is the persistence surface this handler needs. Declared
// here (not imported from root) so the extracted package does not
// import root.
type Storage interface {
	ListUsersByOrganization(ctx context.Context, orgID models.ULID, offset, limit int, f models.SCIMUserFilter) ([]models.User, int, error)
	UserByID(ctx context.Context, id models.ULID) (*models.User, error)
	UserByEmail(ctx context.Context, email string) (*models.User, error)
	CreateUser(ctx context.Context, u models.User) (models.User, error)
	UpsertOrganizationMember(ctx context.Context, m models.OrganizationMember) error
	DeleteOrganizationMember(ctx context.Context, orgID, userID models.ULID) error
	OrganizationMemberRole(ctx context.Context, orgID, userID models.ULID) (string, error)
	RolesForUser(ctx context.Context, userID models.ULID, orgID *models.ULID) ([]models.Role, error)
	RoleByID(ctx context.Context, id models.ULID) (*models.Role, error)
	RolesByOrganization(ctx context.Context, orgID *models.ULID) ([]models.Role, error)
	RevokeSession(ctx context.Context, id models.ULID) error
}

// RBACService is the role-mutation surface used by the user / role
// endpoints.
type RBACService interface {
	GrantRole(ctx context.Context, actorID, userID, roleID models.ULID) error
	RevokeRole(ctx context.Context, actorID, userID, roleID models.ULID) error
	CreateRole(ctx context.Context, orgID models.ULID, name, description string, permissions []string) (models.Role, error)
	UpdateRole(ctx context.Context, roleID models.ULID, name, description string, permissions []string) (models.Role, error)
	DeleteRole(ctx context.Context, roleID models.ULID) error
}

// AuditService is the audit query + emit surface.
type AuditService interface {
	QueryAudit(ctx context.Context, q models.AuditQuery) ([]models.AuditEvent, string, error)
	EmitAudit(ctx context.Context, action string, target models.TargetRef, meta map[string]any)
	HashEmailForAudit(email string) string
}

// UserFromCtx pulls the authenticated user from the request context.
type UserFromCtx func(r *http.Request) (*models.User, bool)

// SessionFromCtx pulls the authenticated session from the request
// context.
type SessionFromCtx func(r *http.Request) (*models.Session, bool)

// PermissionGate returns a middleware that rejects requests whose
// session lacks the named permission.
type PermissionGate func(permission string) func(http.Handler) http.Handler

// MountAgents wires the sibling internal/agent/handlers Mount onto an
// existing chi router scoped under /admin/v1/organizations/{orgID}.
// Supplied by root because the agent handler has its own
// constructor + service dependencies.
type MountAgents func(r chi.Router)

// Handler owns the 12 /admin/v1 endpoints (plus the requireOrgMatch
// middleware that gates the entire /organizations/{orgID} subtree).
type Handler struct {
	storage     Storage
	rbac        RBACService
	audit       AuditService
	pathPrefix  string
	userFromCtx UserFromCtx
	sessFromCtx SessionFromCtx
}

// New constructs a Handler. pathPrefix is the operator-supplied
// /admin path override (defaults to /admin/v1 when empty).
func New(
	storage Storage,
	rbac RBACService,
	audit AuditService,
	pathPrefix string,
	userFromCtx UserFromCtx,
	sessFromCtx SessionFromCtx,
) *Handler {
	if pathPrefix == "" {
		pathPrefix = "/admin/v1"
	} else {
		pathPrefix = strings.TrimRight(pathPrefix, "/")
	}
	return &Handler{
		storage:     storage,
		rbac:        rbac,
		audit:       audit,
		pathPrefix:  pathPrefix,
		userFromCtx: userFromCtx,
		sessFromCtx: sessFromCtx,
	}
}

// Mount wires the entire /admin/v1 tree under r. requireAuth wraps
// every route; requirePermission gates each endpoint per the v1.0
// spec section 9 table. mountAgents (optional, may be nil) attaches
// the agent + delegation subroutes under the same
// /organizations/{orgID} scope.
func (h *Handler) Mount(r chi.Router, requireAuth func(http.Handler) http.Handler, requirePermission PermissionGate, mountAgents MountAgents) {
	r.Route(h.pathPrefix, func(r chi.Router) {
		r.Use(requireAuth)
		r.Route("/organizations/{orgID}", func(r chi.Router) {
			r.Use(h.requireOrgMatch())
			r.With(requirePermission(models.PermissionUsersRead)).Get("/users", h.listUsers)
			r.With(requirePermission(models.PermissionUsersRead)).Get("/users/{userID}", h.getUser)
			r.With(requirePermission(models.PermissionUsersInvite)).Post("/users", h.inviteUser)
			r.With(requirePermission(models.PermissionUsersAdmin)).Patch("/users/{userID}", h.patchUser)
			r.With(requirePermission(models.PermissionUsersAdmin)).Delete("/users/{userID}", h.removeUser)

			r.With(requirePermission(models.PermissionSessionsRevoke)).Get("/sessions", h.listSessions)
			r.With(requirePermission(models.PermissionSessionsRevoke)).Delete("/sessions/{sessionID}", h.revokeSession)

			r.With(requirePermission(models.PermissionRolesRead)).Get("/roles", h.listRoles)
			r.With(requirePermission(models.PermissionRolesAdmin)).Post("/roles", h.createRole)
			r.With(requirePermission(models.PermissionRolesAdmin)).Patch("/roles/{roleID}", h.updateRole)
			r.With(requirePermission(models.PermissionRolesAdmin)).Delete("/roles/{roleID}", h.deleteRole)

			r.With(requirePermission(models.PermissionAuditRead)).Get("/audit", h.queryAudit)
			r.With(requirePermission(models.PermissionUsersRead)).Get("/oauth_accounts", h.listOAuthAccounts)

			if mountAgents != nil {
				mountAgents(r)
			}
		})
	})
}

// requireOrgMatch enforces that the session's active_organization_id
// equals the path's {orgID}. super_admin bypasses the check.
func (h *Handler) requireOrgMatch() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			orgID, ok := httpx.ParseULIDPath(r, "orgID")
			if !ok {
				admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid orgID", "")
				return
			}
			user, _ := h.userFromCtx(r)
			if user != nil {
				roles, err := h.storage.RolesForUser(r.Context(), user.ID, nil)
				if err == nil {
					for _, role := range roles {
						if role.Name == models.SystemRoleSuperAdmin {
							next.ServeHTTP(w, r)
							return
						}
					}
				}
			}
			sess, ok := h.sessFromCtx(r)
			if !ok || sess == nil {
				admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
				return
			}
			if sess.ActiveOrganizationID == nil {
				admin.Write(w, http.StatusForbidden, admin.CodeNoActiveOrg, "session has no active organization", "")
				return
			}
			if *sess.ActiveOrganizationID != orgID {
				admin.Write(w, http.StatusForbidden, admin.CodeOrgMismatch, "session organization does not match path organization", "")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---------- users ----------

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	limit := parseLimit(r)
	offset := parseOffset(r)
	users, _, err := h.storage.ListUsersByOrganization(r.Context(), orgID, offset, limit, models.SCIMUserFilter{})
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	type response struct {
		Users []models.User `json:"users"`
		Next  string        `json:"next,omitempty"`
	}
	resp := response{Users: users}
	if len(users) == limit {
		resp.Next = strconv.Itoa(offset + limit)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	userID, ok := httpx.ParseULIDPath(r, "userID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid userID", "")
		return
	}
	if _, err := h.storage.OrganizationMemberRole(r.Context(), orgID, userID); err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeUserNotInOrg, "user is not a member of this organization", "")
		return
	}
	u, err := h.storage.UserByID(r.Context(), userID)
	if err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, err.Error(), "")
		return
	}
	orgIDCp := orgID
	roles, err := h.storage.RolesForUser(r.Context(), userID, &orgIDCp)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	type response struct {
		models.User
		Roles []models.Role `json:"roles"`
	}
	httpx.WriteJSON(w, http.StatusOK, response{User: *u, Roles: roles})
}

func (h *Handler) inviteUser(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	var body struct {
		Email  string `json:"email"`
		RoleID string `json:"roleId,omitempty"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	if body.Email == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "email required", "")
		return
	}
	now := time.Now()
	u, err := h.storage.UserByEmail(r.Context(), body.Email)
	if err != nil {
		if !errors.Is(err, models.ErrStorageNotFound) {
			admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
			return
		}
		newUser := models.User{ID: internalulid.New(), Email: body.Email, CreatedAt: now, UpdatedAt: now}
		created, err := h.storage.CreateUser(r.Context(), newUser)
		if err != nil {
			admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
			return
		}
		u = &created
	}
	if err := h.storage.UpsertOrganizationMember(r.Context(), models.OrganizationMember{
		OrganizationID: orgID,
		UserID:         u.ID,
		Role:           models.OrgRoleMember,
		JoinedAt:       now,
	}); err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	if body.RoleID != "" {
		roleID, err := ulid.Parse(body.RoleID)
		if err != nil {
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid roleId", "")
			return
		}
		actor, _ := h.userFromCtx(r)
		actorID := models.ULID{}
		if actor != nil {
			actorID = actor.ID
		}
		if err := h.rbac.GrantRole(r.Context(), actorID, u.ID, roleID); err != nil {
			admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
			return
		}
	}
	meta := map[string]any{"email_hash": h.audit.HashEmailForAudit(body.Email)}
	if body.RoleID != "" {
		meta["role_id"] = body.RoleID
	}
	h.audit.EmitAudit(r.Context(), "user.invited", models.TargetRef{Type: "user", ID: u.ID.String()}, meta)
	httpx.WriteJSON(w, http.StatusCreated, u)
}

func (h *Handler) patchUser(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	userID, ok := httpx.ParseULIDPath(r, "userID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid userID", "")
		return
	}
	if _, err := h.storage.OrganizationMemberRole(r.Context(), orgID, userID); err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeUserNotInOrg, "user is not a member of this organization", "")
		return
	}
	var body struct {
		Status  string   `json:"status,omitempty"`
		RoleIDs []string `json:"roleIds,omitempty"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	actor, _ := h.userFromCtx(r)
	actorID := models.ULID{}
	if actor != nil {
		actorID = actor.ID
	}
	if body.RoleIDs != nil {
		orgIDCp := orgID
		current, err := h.storage.RolesForUser(r.Context(), userID, &orgIDCp)
		if err != nil {
			admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
			return
		}
		want := map[models.ULID]struct{}{}
		for _, rid := range body.RoleIDs {
			parsed, err := ulid.Parse(rid)
			if err != nil {
				admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid roleId: "+rid, "")
				return
			}
			role, err := h.storage.RoleByID(r.Context(), parsed)
			if err != nil || role == nil {
				admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "role not found: "+rid, "")
				return
			}
			if role.OrganizationID == nil || *role.OrganizationID != orgID {
				admin.Write(w, http.StatusNotFound, admin.CodeUserNotInOrg, "role does not belong to this organization", "")
				return
			}
			want[parsed] = struct{}{}
		}
		have := map[models.ULID]struct{}{}
		for _, role := range current {
			have[role.ID] = struct{}{}
		}
		for id := range want {
			if _, ok := have[id]; !ok {
				if err := h.rbac.GrantRole(r.Context(), actorID, userID, id); err != nil {
					admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
					return
				}
			}
		}
		for id := range have {
			if _, ok := want[id]; !ok {
				if err := h.rbac.RevokeRole(r.Context(), actorID, userID, id); err != nil {
					admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
					return
				}
			}
		}
	}
	u, err := h.storage.UserByID(r.Context(), userID)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	orgIDCp := orgID
	roles, _ := h.storage.RolesForUser(r.Context(), userID, &orgIDCp)
	type response struct {
		models.User
		Roles []models.Role `json:"roles"`
	}
	httpx.WriteJSON(w, http.StatusOK, response{User: *u, Roles: roles})
}

func (h *Handler) removeUser(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	userID, ok := httpx.ParseULIDPath(r, "userID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid userID", "")
		return
	}
	if err := h.storage.DeleteOrganizationMember(r.Context(), orgID, userID); err != nil {
		if errors.Is(err, models.ErrStorageNotFound) {
			admin.Write(w, http.StatusNotFound, admin.CodeUserNotInOrg, "user not in organization", "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	h.audit.EmitAudit(r.Context(), "organization.member.removed", models.TargetRef{Type: "user", ID: userID.String()}, map[string]any{
		"org_id": orgID.String(),
	})
	w.WriteHeader(http.StatusNoContent)
}

// ---------- sessions ----------

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.URL.Query().Get("user_id")
	if userIDStr == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "user_id query param required", "")
		return
	}
	if _, err := ulid.Parse(userIDStr); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid user_id", "")
		return
	}
	type response struct {
		Sessions []models.Session `json:"sessions"`
		Next     string           `json:"next,omitempty"`
	}
	httpx.WriteJSON(w, http.StatusOK, response{Sessions: []models.Session{}})
}

func (h *Handler) revokeSession(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := httpx.ParseULIDPath(r, "sessionID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid sessionID", "")
		return
	}
	if err := h.storage.RevokeSession(r.Context(), sessionID); err != nil {
		if errors.Is(err, models.ErrStorageNotFound) {
			admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "session not found", "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	h.audit.EmitAudit(r.Context(), "session.revoked", models.TargetRef{Type: "session", ID: sessionID.String()}, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------- roles ----------

func (h *Handler) listRoles(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	orgIDCp := orgID
	roles, err := h.storage.RolesByOrganization(r.Context(), &orgIDCp)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	type response struct {
		Roles []models.Role `json:"roles"`
		Next  string        `json:"next,omitempty"`
	}
	httpx.WriteJSON(w, http.StatusOK, response{Roles: roles})
}

func (h *Handler) createRole(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	if body.Name == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "name required", "")
		return
	}
	role, err := h.rbac.CreateRole(r.Context(), orgID, body.Name, body.Description, body.Permissions)
	if err != nil {
		if errors.Is(err, models.ErrUnknownPermission) {
			admin.Write(w, http.StatusBadRequest, admin.CodeUnknownPermission, err.Error(), "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, role)
}

func (h *Handler) updateRole(w http.ResponseWriter, r *http.Request) {
	roleID, ok := httpx.ParseULIDPath(r, "roleID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid roleID", "")
		return
	}
	var body struct {
		Name        string   `json:"name,omitempty"`
		Description string   `json:"description,omitempty"`
		Permissions []string `json:"permissions,omitempty"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	role, err := h.rbac.UpdateRole(r.Context(), roleID, body.Name, body.Description, body.Permissions)
	if err != nil {
		if errors.Is(err, models.ErrUnknownPermission) {
			admin.Write(w, http.StatusBadRequest, admin.CodeUnknownPermission, err.Error(), "")
			return
		}
		if errors.Is(err, models.ErrStorageNotFound) {
			admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "role not found", "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, role)
}

func (h *Handler) deleteRole(w http.ResponseWriter, r *http.Request) {
	roleID, ok := httpx.ParseULIDPath(r, "roleID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid roleID", "")
		return
	}
	if err := h.rbac.DeleteRole(r.Context(), roleID); err != nil {
		if errors.Is(err, models.ErrRoleInUse) {
			admin.Write(w, http.StatusConflict, admin.CodeRoleInUse, "role is the sole grantor of users:admin", "")
			return
		}
		if errors.Is(err, models.ErrStorageNotFound) {
			admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "role not found", "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- audit ----------

func (h *Handler) queryAudit(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	q := models.AuditQuery{
		Action:     r.URL.Query().Get("action"),
		TargetType: r.URL.Query().Get("target_type"),
		TargetID:   r.URL.Query().Get("target_id"),
		After:      r.URL.Query().Get("cursor"),
		Limit:      parseLimit(r),
	}
	orgIDCp := orgID
	q.OrganizationID = &orgIDCp
	if v := r.URL.Query().Get("actor"); v != "" {
		id, err := ulid.Parse(v)
		if err != nil {
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid actor", "")
			return
		}
		q.ActorUserID = &id
	}
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid since", "")
			return
		}
		q.Since = &t
	}
	if v := r.URL.Query().Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid until", "")
			return
		}
		q.Until = &t
	}
	events, next, err := h.audit.QueryAudit(r.Context(), q)
	if err != nil {
		if errors.Is(err, models.ErrBadCursor) {
			admin.Write(w, http.StatusBadRequest, admin.CodeBadCursor, err.Error(), "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	h.audit.EmitAudit(r.Context(), "audit.queried", models.TargetRef{Type: "audit"}, map[string]any{
		"result_count": len(events),
		"filters": map[string]any{
			"action":      q.Action,
			"target_type": q.TargetType,
			"target_id":   q.TargetID,
		},
	})
	type response struct {
		Events []models.AuditEvent `json:"events"`
		Next   string              `json:"next,omitempty"`
	}
	httpx.WriteJSON(w, http.StatusOK, response{Events: events, Next: next})
}

// ---------- oauth accounts ----------

func (h *Handler) listOAuthAccounts(w http.ResponseWriter, _ *http.Request) {
	// The Storage interface does not expose
	// ListOAuthAccountsByOrganization or ListOAuthAccountsByUser. v1.0
	// returns an empty list to honour the contract; operators with
	// custom adapters can shadow this endpoint.
	type response struct {
		Accounts []models.OAuthAccount `json:"accounts"`
	}
	httpx.WriteJSON(w, http.StatusOK, response{Accounts: []models.OAuthAccount{}})
}

// ---------- helpers ----------

func parseLimit(r *http.Request) int {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return 50
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 50
	}
	if n > 200 {
		return 200
	}
	return n
}

func parseOffset(r *http.Request) int {
	v := r.URL.Query().Get("cursor")
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
