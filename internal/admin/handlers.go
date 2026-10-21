// Package admin serves the /admin/v1 organization-scoped API: user, session, role, audit and OAuth
// account management. The agent and delegation admin routes live in a sibling package and mount as
// a subtree.
package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/admin"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/models"
	internalulid "github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"
)

// Storage is the persistence surface this handler needs. It is declared here so the package does
// not import root.
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

// sessionLister is the optional session-list capability; storages without it
// list nothing.
type sessionLister interface {
	ListUserSessions(ctx context.Context, userID models.ULID) ([]models.Session, error)
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

// MountAgents wires the agent and delegation subroutes under /admin/v1/organizations/{orgID}. Root
// supplies it.
type MountAgents func(r chi.Router)

// Lifecycle is the optional account lifecycle surface. With it, PATCH /users/{userID} accepts
// mustChangePassword and disabled, and DELETE /users/{userID}/account deletes the account.
// Disabling and deleting require super_admin.
type Lifecycle interface {
	SetMustChangePassword(ctx context.Context, userID models.ULID, required bool) error
	DisableUser(ctx context.Context, userID models.ULID) error
	EnableUser(ctx context.Context, userID models.ULID) error
	DeleteUser(ctx context.Context, userID models.ULID) error
}

// WithLifecycle enables the account lifecycle endpoints. It returns h.
func (h *Handler) WithLifecycle(l Lifecycle) *Handler {
	h.lifecycle = l
	return h
}

// Handler owns the 12 /admin/v1 endpoints (plus the requireOrgMatch
// middleware that gates the entire /organizations/{orgID} subtree).
type Handler struct {
	storage     Storage
	rbac        RBACService
	audit       AuditService
	pathPrefix  string
	userFromCtx UserFromCtx
	sessFromCtx SessionFromCtx
	lifecycle   Lifecycle
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

// Mount wires the whole /admin/v1 tree under r. Each endpoint is gated by requirePermission, per
// the RBAC seed table.
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
			if h.lifecycle != nil {
				r.With(requirePermission(models.PermissionUsersAdmin)).Delete("/users/{userID}/account", h.deleteUserAccount)
			}

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

// users

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
		Status             string   `json:"status,omitempty"`
		RoleIDs            []string `json:"roleIds,omitempty"`
		MustChangePassword *bool    `json:"mustChangePassword,omitempty"`
		Disabled           *bool    `json:"disabled,omitempty"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	if !h.applyLifecycle(w, r, userID, body.MustChangePassword, body.Disabled) {
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

// isSuperAdmin reports whether the caller holds the global super_admin role.
func (h *Handler) isSuperAdmin(r *http.Request) bool {
	user, _ := h.userFromCtx(r)
	if user == nil {
		return false
	}
	roles, err := h.storage.RolesForUser(r.Context(), user.ID, nil)
	if err != nil {
		return false
	}
	for _, role := range roles {
		if role.Name == models.SystemRoleSuperAdmin {
			return true
		}
	}
	return false
}

// applyLifecycle applies the optional mustChangePassword and disabled fields
// of a PATCH body. It writes the error response and returns false on failure.
func (h *Handler) applyLifecycle(w http.ResponseWriter, r *http.Request, userID models.ULID, must, disabled *bool) bool {
	if must == nil && disabled == nil {
		return true
	}
	if h.lifecycle == nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeUnsupportedAction, "account lifecycle is not enabled", "")
		return false
	}
	if disabled != nil && !h.isSuperAdmin(r) {
		admin.Write(w, http.StatusForbidden, admin.CodeForbidden, "disabling an account requires the super_admin role", "")
		return false
	}
	ctx := r.Context()
	if must != nil {
		if err := h.lifecycle.SetMustChangePassword(ctx, userID, *must); err != nil {
			h.lifecycleError(w, err)
			return false
		}
	}
	if disabled != nil {
		var err error
		if *disabled {
			err = h.lifecycle.DisableUser(ctx, userID)
		} else {
			err = h.lifecycle.EnableUser(ctx, userID)
		}
		if err != nil {
			h.lifecycleError(w, err)
			return false
		}
	}
	return true
}

func (h *Handler) lifecycleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, models.ErrStorageNotFound):
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "user not found", "")
	case errors.Is(err, models.ErrLastOwner):
		admin.Write(w, http.StatusConflict, admin.CodeRoleInUse, "user is the last owner of an organization", "")
	case errors.Is(err, models.ErrStorageMissingCapability), errors.Is(err, models.ErrAccountStateDisabled):
		admin.Write(w, http.StatusNotImplemented, admin.CodeUnsupportedAction, "storage does not support this action", "")
	default:
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, "internal error", "")
	}
}

// deleteUserAccount permanently deletes the account and everything that
// belongs to it. Unlike removeUser it is global, so it needs super_admin.
func (h *Handler) deleteUserAccount(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	userID, ok := httpx.ParseULIDPath(r, "userID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid userID", "")
		return
	}
	if !h.isSuperAdmin(r) {
		admin.Write(w, http.StatusForbidden, admin.CodeForbidden, "deleting an account requires the super_admin role", "")
		return
	}
	if actor, _ := h.userFromCtx(r); actor != nil && actor.ID == userID {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "use DELETE /account to delete your own account", "")
		return
	}
	if _, err := h.storage.OrganizationMemberRole(r.Context(), orgID, userID); err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeUserNotInOrg, "user is not a member of this organization", "")
		return
	}
	if err := h.lifecycle.DeleteUser(r.Context(), userID); err != nil {
		h.lifecycleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

// sessions

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
	sessions := []models.Session{}
	if l, ok := h.storage.(sessionLister); ok {
		userID, _ := ulid.Parse(userIDStr)
		rows, err := l.ListUserSessions(r.Context(), userID)
		if err != nil {
			admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
			return
		}
		if rows != nil {
			sessions = rows
		}
	}
	httpx.WriteJSON(w, http.StatusOK, response{Sessions: sessions})
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

// roles

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

// audit

func (h *Handler) queryAudit(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	q := models.AuditQuery{
		Action:     r.URL.Query().Get("action"),
		TargetType: r.URL.Query().Get("target_type"),
		TargetID:   r.URL.Query().Get("target_id"),
		Event:      r.URL.Query().Get("event"),
		Order:      r.URL.Query().Get("order"),
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
	if kind, hash := r.URL.Query().Get("provenance_kind"), r.URL.Query().Get("provenance_hash"); kind != "" || hash != "" {
		q.Provenance = &models.ProvenanceFilter{Kind: kind, Hash: hash}
	}
	events, next, err := h.audit.QueryAudit(r.Context(), q)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrBadProvenanceFilter):
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid provenance filter: kind must be user_message, tool_output, retrieved_document or agent, and hash 64 lowercase hex characters", "")
		case errors.Is(err, models.ErrAuditProvenanceUnsupported):
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "this storage backend does not support the provenance filter", "")
		case errors.Is(err, models.ErrBadCursor):
			admin.Write(w, http.StatusBadRequest, admin.CodeBadCursor, err.Error(), "")
		case errors.Is(err, models.ErrBadAuditOrder):
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid order: use asc or desc", "")
		case errors.Is(err, models.ErrAuditOrderUnsupported):
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "this storage backend does not support order=asc, the event filter or c1 cursors", "")
		default:
			admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		}
		return
	}
	h.audit.EmitAudit(r.Context(), "audit.queried", models.TargetRef{Type: "audit"}, map[string]any{
		"result_count": len(events),
		"filters": map[string]any{
			"action":      q.Action,
			"target_type": q.TargetType,
			"target_id":   q.TargetID,
			"event":       q.Event,
			"order":       q.Order,
			"provenance":  q.Provenance != nil,
		},
	})
	type response struct {
		Events []models.AuditEvent `json:"events"`
		// Next is the original name of NextCursor and carries the same value.
		Next       string `json:"next,omitempty"`
		NextCursor string `json:"next_cursor,omitempty"`
	}
	httpx.WriteJSON(w, http.StatusOK, response{Events: events, Next: next, NextCursor: next})
}

// oauth accounts

func (h *Handler) listOAuthAccounts(w http.ResponseWriter, _ *http.Request) {
	// v1.0 returns an empty list here because Storage has no OAuth account listing. Custom adapters
	// can shadow this endpoint.
	type response struct {
		Accounts []models.OAuthAccount `json:"accounts"`
	}
	httpx.WriteJSON(w, http.StatusOK, response{Accounts: []models.OAuthAccount{}})
}

// helpers

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
