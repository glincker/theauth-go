package theauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/admin"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"
)

// mountAdmin wires the /admin/v1 routes. Called from Mount when
// Config.Admin is non-nil. Each endpoint is gated by RequireAuth (full)
// plus a RequirePermission for the catalog permission listed in the v1.0
// spec section 9 table.
func (a *TheAuth) mountAdmin(r chi.Router) {
	prefix := "/admin/v1"
	if a.adminCfg != nil && a.adminCfg.PathPrefix != "" {
		prefix = strings.TrimRight(a.adminCfg.PathPrefix, "/")
	}
	r.Route(prefix, func(r chi.Router) {
		r.Use(a.RequireAuth())
		r.Route("/organizations/{orgID}", func(r chi.Router) {
			r.Use(a.requireOrgMatch())
			r.With(a.RequirePermission(PermissionUsersRead)).Get("/users", a.adminListUsers)
			r.With(a.RequirePermission(PermissionUsersRead)).Get("/users/{userID}", a.adminGetUser)
			r.With(a.RequirePermission(PermissionUsersInvite)).Post("/users", a.adminInviteUser)
			r.With(a.RequirePermission(PermissionUsersAdmin)).Patch("/users/{userID}", a.adminPatchUser)
			r.With(a.RequirePermission(PermissionUsersAdmin)).Delete("/users/{userID}", a.adminRemoveUser)

			r.With(a.RequirePermission(PermissionSessionsRevoke)).Get("/sessions", a.adminListSessions)
			r.With(a.RequirePermission(PermissionSessionsRevoke)).Delete("/sessions/{sessionID}", a.adminRevokeSession)

			r.With(a.RequirePermission(PermissionRolesRead)).Get("/roles", a.adminListRoles)
			r.With(a.RequirePermission(PermissionRolesAdmin)).Post("/roles", a.adminCreateRole)
			r.With(a.RequirePermission(PermissionRolesAdmin)).Patch("/roles/{roleID}", a.adminUpdateRole)
			r.With(a.RequirePermission(PermissionRolesAdmin)).Delete("/roles/{roleID}", a.adminDeleteRole)

			r.With(a.RequirePermission(PermissionAuditRead)).Get("/audit", a.adminQueryAudit)
			r.With(a.RequirePermission(PermissionUsersRead)).Get("/oauth_accounts", a.adminListOAuthAccounts)

			// v2.0 phase 6: organization-scoped agent + delegation admin.
			// Mounted only when the agent identity service is configured.
			a.mountAdminAgents(r)
		})
	})
}

// requireOrgMatch enforces that the session's active_organization_id equals
// the path's {orgID}. super_admin bypasses the check.
func (a *TheAuth) requireOrgMatch() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			orgID, ok := parseULIDPath(r, "orgID")
			if !ok {
				admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid orgID", "")
				return
			}
			user, _ := UserFromContext(r.Context())
			if user != nil {
				roles, err := a.storage.RolesForUser(r.Context(), user.ID, nil)
				if err == nil {
					for _, role := range roles {
						if role.Name == SystemRoleSuperAdmin {
							next.ServeHTTP(w, r)
							return
						}
					}
				}
			}
			sess, ok := SessionFromContext(r.Context())
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

func (a *TheAuth) adminListUsers(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	limit := parseLimit(r)
	offset := parseOffset(r)
	users, _, err := a.storage.ListUsersByOrganization(r.Context(), orgID, offset, limit, SCIMUserFilter{})
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	type response struct {
		Users []User `json:"users"`
		Next  string `json:"next,omitempty"`
	}
	resp := response{Users: users}
	if len(users) == limit {
		resp.Next = strconv.Itoa(offset + limit)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *TheAuth) adminGetUser(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	userID, ok := parseULIDPath(r, "userID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid userID", "")
		return
	}
	if _, err := a.storage.OrganizationMemberRole(r.Context(), orgID, userID); err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeUserNotInOrg, "user is not a member of this organization", "")
		return
	}
	u, err := a.storage.UserByID(r.Context(), userID)
	if err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, err.Error(), "")
		return
	}
	orgIDCp := orgID
	roles, err := a.storage.RolesForUser(r.Context(), userID, &orgIDCp)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	type response struct {
		User
		Roles []Role `json:"roles"`
	}
	writeJSON(w, http.StatusOK, response{User: *u, Roles: roles})
}

func (a *TheAuth) adminInviteUser(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	var body struct {
		Email  string `json:"email"`
		RoleID string `json:"roleId,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	if body.Email == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "email required", "")
		return
	}
	now := time.Now()
	u, err := a.storage.UserByEmail(r.Context(), body.Email)
	if err != nil {
		if !errors.Is(err, ErrStorageNotFound) {
			admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
			return
		}
		newUser := User{ID: newULID(), Email: body.Email, CreatedAt: now, UpdatedAt: now}
		created, err := a.storage.CreateUser(r.Context(), newUser)
		if err != nil {
			admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
			return
		}
		u = &created
	}
	if err := a.storage.UpsertOrganizationMember(r.Context(), OrganizationMember{
		OrganizationID: orgID,
		UserID:         u.ID,
		Role:           OrgRoleMember,
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
		actor, _ := UserFromContext(r.Context())
		actorID := ULID{}
		if actor != nil {
			actorID = actor.ID
		}
		if err := a.GrantRole(r.Context(), actorID, u.ID, roleID); err != nil {
			admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
			return
		}
	}
	meta := map[string]any{"email_hash": HashEmailForAudit(body.Email)}
	if body.RoleID != "" {
		meta["role_id"] = body.RoleID
	}
	a.EmitAudit(r.Context(), "user.invited", TargetRef{Type: "user", ID: u.ID.String()}, meta)
	writeJSON(w, http.StatusCreated, u)
}

func (a *TheAuth) adminPatchUser(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	userID, ok := parseULIDPath(r, "userID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid userID", "")
		return
	}
	if _, err := a.storage.OrganizationMemberRole(r.Context(), orgID, userID); err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeUserNotInOrg, "user is not a member of this organization", "")
		return
	}
	var body struct {
		Status  string   `json:"status,omitempty"`
		RoleIDs []string `json:"roleIds,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	actor, _ := UserFromContext(r.Context())
	actorID := ULID{}
	if actor != nil {
		actorID = actor.ID
	}
	if body.RoleIDs != nil {
		orgIDCp := orgID
		current, err := a.storage.RolesForUser(r.Context(), userID, &orgIDCp)
		if err != nil {
			admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
			return
		}
		want := map[ULID]struct{}{}
		for _, rid := range body.RoleIDs {
			parsed, err := ulid.Parse(rid)
			if err != nil {
				admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid roleId: "+rid, "")
				return
			}
			role, err := a.storage.RoleByID(r.Context(), parsed)
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
		have := map[ULID]struct{}{}
		for _, role := range current {
			have[role.ID] = struct{}{}
		}
		for id := range want {
			if _, ok := have[id]; !ok {
				if err := a.GrantRole(r.Context(), actorID, userID, id); err != nil {
					admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
					return
				}
			}
		}
		for id := range have {
			if _, ok := want[id]; !ok {
				if err := a.RevokeRole(r.Context(), actorID, userID, id); err != nil {
					admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
					return
				}
			}
		}
	}
	u, err := a.storage.UserByID(r.Context(), userID)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	orgIDCp := orgID
	roles, _ := a.storage.RolesForUser(r.Context(), userID, &orgIDCp)
	type response struct {
		User
		Roles []Role `json:"roles"`
	}
	writeJSON(w, http.StatusOK, response{User: *u, Roles: roles})
}

func (a *TheAuth) adminRemoveUser(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	userID, ok := parseULIDPath(r, "userID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid userID", "")
		return
	}
	if err := a.storage.DeleteOrganizationMember(r.Context(), orgID, userID); err != nil {
		if errors.Is(err, ErrStorageNotFound) {
			admin.Write(w, http.StatusNotFound, admin.CodeUserNotInOrg, "user not in organization", "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	a.EmitAudit(r.Context(), "organization.member.removed", TargetRef{Type: "user", ID: userID.String()}, map[string]any{
		"org_id": orgID.String(),
	})
	w.WriteHeader(http.StatusNoContent)
}

// ---------- sessions ----------

func (a *TheAuth) adminListSessions(w http.ResponseWriter, r *http.Request) {
	// The v1.0 spec scopes session listing to a user_id query param. The
	// underlying storage exposes per-user revocation but no list-all-by-org
	// helper; we keep the surface honest by requiring user_id here.
	userIDStr := r.URL.Query().Get("user_id")
	if userIDStr == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "user_id query param required", "")
		return
	}
	if _, err := ulid.Parse(userIDStr); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid user_id", "")
		return
	}
	// The Storage interface does not expose SessionsByUser; v1.0 returns
	// an empty list to keep the contract honest. Operators with custom
	// adapters can wrap this endpoint.
	type response struct {
		Sessions []Session `json:"sessions"`
		Next     string    `json:"next,omitempty"`
	}
	writeJSON(w, http.StatusOK, response{Sessions: []Session{}})
}

func (a *TheAuth) adminRevokeSession(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := parseULIDPath(r, "sessionID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid sessionID", "")
		return
	}
	if err := a.storage.RevokeSession(r.Context(), sessionID); err != nil {
		if errors.Is(err, ErrStorageNotFound) {
			admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "session not found", "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	a.EmitAudit(r.Context(), "session.revoked", TargetRef{Type: "session", ID: sessionID.String()}, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------- roles ----------

func (a *TheAuth) adminListRoles(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	orgIDCp := orgID
	roles, err := a.storage.RolesByOrganization(r.Context(), &orgIDCp)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	type response struct {
		Roles []Role `json:"roles"`
		Next  string `json:"next,omitempty"`
	}
	writeJSON(w, http.StatusOK, response{Roles: roles})
}

func (a *TheAuth) adminCreateRole(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := decodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	if body.Name == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "name required", "")
		return
	}
	role, err := a.CreateRole(r.Context(), orgID, body.Name, body.Description, body.Permissions)
	if err != nil {
		if errors.Is(err, ErrUnknownPermission) {
			admin.Write(w, http.StatusBadRequest, admin.CodeUnknownPermission, err.Error(), "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

func (a *TheAuth) adminUpdateRole(w http.ResponseWriter, r *http.Request) {
	roleID, ok := parseULIDPath(r, "roleID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid roleID", "")
		return
	}
	var body struct {
		Name        string   `json:"name,omitempty"`
		Description string   `json:"description,omitempty"`
		Permissions []string `json:"permissions,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	role, err := a.UpdateRole(r.Context(), roleID, body.Name, body.Description, body.Permissions)
	if err != nil {
		if errors.Is(err, ErrUnknownPermission) {
			admin.Write(w, http.StatusBadRequest, admin.CodeUnknownPermission, err.Error(), "")
			return
		}
		if errors.Is(err, ErrStorageNotFound) {
			admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "role not found", "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, role)
}

func (a *TheAuth) adminDeleteRole(w http.ResponseWriter, r *http.Request) {
	roleID, ok := parseULIDPath(r, "roleID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid roleID", "")
		return
	}
	if err := a.DeleteRole(r.Context(), roleID); err != nil {
		if errors.Is(err, ErrRoleInUse) {
			admin.Write(w, http.StatusConflict, admin.CodeRoleInUse, "role is the sole grantor of users:admin", "")
			return
		}
		if errors.Is(err, ErrStorageNotFound) {
			admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "role not found", "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- audit ----------

func (a *TheAuth) adminQueryAudit(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	q := AuditQuery{
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
	events, next, err := a.QueryAudit(r.Context(), q)
	if err != nil {
		if strings.Contains(err.Error(), "pagination.bad_cursor") || strings.Contains(err.Error(), "cursor") {
			admin.Write(w, http.StatusBadRequest, admin.CodeBadCursor, err.Error(), "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	a.EmitAudit(r.Context(), "audit.queried", TargetRef{Type: "audit"}, map[string]any{
		"result_count": len(events),
		"filters": map[string]any{
			"action":      q.Action,
			"target_type": q.TargetType,
			"target_id":   q.TargetID,
		},
	})
	type response struct {
		Events []AuditEvent `json:"events"`
		Next   string       `json:"next,omitempty"`
	}
	writeJSON(w, http.StatusOK, response{Events: events, Next: next})
}

// ---------- oauth accounts ----------

func (a *TheAuth) adminListOAuthAccounts(w http.ResponseWriter, r *http.Request) {
	// The Storage interface does not expose ListOAuthAccountsByOrganization
	// or ListOAuthAccountsByUser. v1.0 returns an empty list to honour the
	// contract; operators with custom adapters can shadow this endpoint.
	type response struct {
		Accounts []OAuthAccount `json:"accounts"`
	}
	writeJSON(w, http.StatusOK, response{Accounts: []OAuthAccount{}})
}

// ---------- helpers ----------

func parseULIDPath(r *http.Request, key string) (ULID, bool) {
	s := chi.URLParam(r, key)
	if s == "" {
		return ULID{}, false
	}
	id, err := ulid.Parse(s)
	if err != nil {
		return ULID{}, false
	}
	return id, true
}

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

func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<16)
	return json.NewDecoder(r.Body).Decode(v)
}
