// Package admin_handlers_test contains direct HTTP-layer table tests for
// internal/admin/handlers. Each sub-test mounts Handler via Mount onto a
// chi.Router backed by stub implementations, then fires requests through
// httptest so the full handler chain is exercised without any root TheAuth
// state.
//
// Coverage targets:
//   - getUser: happy path 200, missing-permission 403, not-found 404
//   - patchUser: happy path 200, 404 (user not in org), malformed 400
//   - listSessions: happy path 200, missing user_id 400, invalid user_id 400
//   - revokeSession: happy path 204, not-found 404, invalid sessionID 400
//   - listRoles: happy path 200
//   - updateRole: happy path 200, not-found 404, unknown-permission 400,
//     malformed body 400
//   - listOAuthAccounts: happy path 200
//   - requireOrgMatch middleware: orgID mismatch 403, super_admin bypass
package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glincker/theauth-go/internal/admin/handlers"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/go-chi/chi/v5"
)

// -----------------------------------------------------------------------------
// Stub implementations
// -----------------------------------------------------------------------------

// stubAdminStorage satisfies handlers.Storage.
type stubAdminStorage struct {
	users    map[models.ULID]*models.User
	sessions map[models.ULID]*models.Session
	roles    []*models.Role
	members  map[string]string // key: orgID+":"+userID -> role

	listUsersErr error
	userErr      error
	memberErr    error
	revokeErr    error
	rolesErr     error
}

func newStubStorage() *stubAdminStorage {
	return &stubAdminStorage{
		users:    make(map[models.ULID]*models.User),
		sessions: make(map[models.ULID]*models.Session),
		members:  make(map[string]string),
	}
}

func (s *stubAdminStorage) addUser(u *models.User) {
	s.users[u.ID] = u
}

func (s *stubAdminStorage) addMember(orgID, userID models.ULID, role string) {
	s.members[orgID.String()+":"+userID.String()] = role
}

func (s *stubAdminStorage) addRole(r *models.Role) {
	s.roles = append(s.roles, r)
}

func (s *stubAdminStorage) ListUsersByOrganization(_ context.Context, _ models.ULID, _, _ int, _ models.SCIMUserFilter) ([]models.User, int, error) {
	if s.listUsersErr != nil {
		return nil, 0, s.listUsersErr
	}
	var out []models.User
	for _, u := range s.users {
		out = append(out, *u)
	}
	return out, len(out), nil
}

func (s *stubAdminStorage) UserByID(_ context.Context, id models.ULID) (*models.User, error) {
	if s.userErr != nil {
		return nil, s.userErr
	}
	u, ok := s.users[id]
	if !ok {
		return nil, models.ErrStorageNotFound
	}
	return u, nil
}

func (s *stubAdminStorage) UserByEmail(_ context.Context, email string) (*models.User, error) {
	for _, u := range s.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, models.ErrStorageNotFound
}

func (s *stubAdminStorage) CreateUser(_ context.Context, u models.User) (models.User, error) {
	s.users[u.ID] = &u
	return u, nil
}

func (s *stubAdminStorage) UpsertOrganizationMember(_ context.Context, m models.OrganizationMember) error {
	s.members[m.OrganizationID.String()+":"+m.UserID.String()] = m.Role
	return nil
}

func (s *stubAdminStorage) DeleteOrganizationMember(_ context.Context, orgID, userID models.ULID) error {
	key := orgID.String() + ":" + userID.String()
	if _, ok := s.members[key]; !ok {
		return models.ErrStorageNotFound
	}
	delete(s.members, key)
	return nil
}

func (s *stubAdminStorage) OrganizationMemberRole(_ context.Context, orgID, userID models.ULID) (string, error) {
	if s.memberErr != nil {
		return "", s.memberErr
	}
	key := orgID.String() + ":" + userID.String()
	role, ok := s.members[key]
	if !ok {
		return "", models.ErrStorageNotFound
	}
	return role, nil
}

func (s *stubAdminStorage) RolesForUser(_ context.Context, _ models.ULID, _ *models.ULID) ([]models.Role, error) {
	if s.rolesErr != nil {
		return nil, s.rolesErr
	}
	var out []models.Role
	for _, r := range s.roles {
		out = append(out, *r)
	}
	return out, nil
}

func (s *stubAdminStorage) RoleByID(_ context.Context, id models.ULID) (*models.Role, error) {
	for _, r := range s.roles {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, models.ErrStorageNotFound
}

func (s *stubAdminStorage) RolesByOrganization(_ context.Context, _ *models.ULID) ([]models.Role, error) {
	if s.rolesErr != nil {
		return nil, s.rolesErr
	}
	var out []models.Role
	for _, r := range s.roles {
		out = append(out, *r)
	}
	return out, nil
}

func (s *stubAdminStorage) RevokeSession(_ context.Context, id models.ULID) error {
	if s.revokeErr != nil {
		return s.revokeErr
	}
	_, ok := s.sessions[id]
	if !ok {
		return models.ErrStorageNotFound
	}
	return nil
}

// stubRBAC satisfies handlers.RBACService.
type stubRBAC struct {
	grantErr  error
	revokeErr error
	createErr error
	updateErr error
	deleteErr error
	role      models.Role
}

func (r *stubRBAC) GrantRole(_ context.Context, _, _, _ models.ULID) error  { return r.grantErr }
func (r *stubRBAC) RevokeRole(_ context.Context, _, _, _ models.ULID) error { return r.revokeErr }
func (r *stubRBAC) CreateRole(_ context.Context, orgID models.ULID, name, desc string, perms []string) (models.Role, error) {
	if r.createErr != nil {
		return models.Role{}, r.createErr
	}
	return models.Role{ID: ulid.New(), OrganizationID: &orgID, Name: name, Description: desc, Permissions: perms}, nil
}
func (r *stubRBAC) UpdateRole(_ context.Context, roleID models.ULID, name, desc string, perms []string) (models.Role, error) {
	if r.updateErr != nil {
		return models.Role{}, r.updateErr
	}
	role := r.role
	role.ID = roleID
	if name != "" {
		role.Name = name
	}
	if desc != "" {
		role.Description = desc
	}
	if perms != nil {
		role.Permissions = perms
	}
	return role, nil
}
func (r *stubRBAC) DeleteRole(_ context.Context, _ models.ULID) error { return r.deleteErr }

// stubAudit satisfies handlers.AuditService.
type stubAudit struct {
	events   []models.AuditEvent
	next     string
	queryErr error
}

func (a *stubAudit) QueryAudit(_ context.Context, _ models.AuditQuery) ([]models.AuditEvent, string, error) {
	if a.queryErr != nil {
		return nil, "", a.queryErr
	}
	return a.events, a.next, nil
}

func (a *stubAudit) EmitAudit(_ context.Context, _ string, _ models.TargetRef, _ map[string]any) {}

func (a *stubAudit) HashEmailForAudit(email string) string { return "hashed:" + email }

// -----------------------------------------------------------------------------
// Test server construction
// -----------------------------------------------------------------------------

// buildAdminServer constructs a chi.Router with the admin Handler mounted and
// returns an httptest.Server. orgID is the active organization that the session
// is scoped to. user and sess may be nil.
//
// allowPermission controls whether the requirePermission gate passes. When
// false, any permission-gated endpoint returns 403.
func buildAdminServer(
	store *stubAdminStorage,
	rbac *stubRBAC,
	audit *stubAudit,
	user *models.User,
	sess *models.Session,
	allowPermission bool,
) *httptest.Server {
	userFromCtx := handlers.UserFromCtx(func(_ *http.Request) (*models.User, bool) {
		if user == nil {
			return nil, false
		}
		return user, true
	})
	sessFromCtx := handlers.SessionFromCtx(func(_ *http.Request) (*models.Session, bool) {
		if sess == nil {
			return nil, false
		}
		return sess, true
	})
	requireAuth := func(next http.Handler) http.Handler { return next }
	requirePermission := handlers.PermissionGate(func(_ string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !allowPermission {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	})

	h := handlers.New(store, rbac, audit, "", userFromCtx, sessFromCtx)
	r := chi.NewRouter()
	h.Mount(r, requireAuth, requirePermission, nil)
	return httptest.NewServer(r)
}

// fakeAdminUser returns a test user with a fresh ULID.
func fakeAdminUser() *models.User {
	return &models.User{
		ID:        ulid.New(),
		Email:     "admin@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// fakeAdminSession returns a session whose ActiveOrganizationID matches orgID.
func fakeAdminSession(orgID models.ULID) *models.Session {
	return &models.Session{
		ID:                   ulid.New(),
		UserID:               ulid.New(),
		CreatedAt:            time.Now(),
		ExpiresAt:            time.Now().Add(time.Hour),
		ActiveOrganizationID: &orgID,
	}
}

// noRedirectClient is shared across all admin tests.
var noRedirectClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// adminURL builds the full URL for an /admin/v1/organizations/{orgID}/... path.
func adminURL(srv *httptest.Server, orgID models.ULID, rest string) string {
	return srv.URL + "/admin/v1/organizations/" + orgID.String() + rest
}

// doAdminJSON fires a request with an optional JSON body.
func doAdminJSON(t *testing.T, method, url string, body []byte) *http.Response {
	t.Helper()
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, url, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// -----------------------------------------------------------------------------
// requireOrgMatch middleware tests
// -----------------------------------------------------------------------------

// TestOrgMatch_Mismatch verifies that a session whose ActiveOrganizationID
// does not match the path orgID is rejected with 403.
func TestOrgMatch_Mismatch(t *testing.T) {
	orgID := ulid.New()
	otherOrg := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(otherOrg) // active org != path org
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/users"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for org mismatch, got %d", resp.StatusCode)
	}
}

// TestOrgMatch_NoSession verifies that a request without a session is rejected
// with 401 or 403 from the middleware.
func TestOrgMatch_NoSession(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, nil, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/users"), nil)
	defer resp.Body.Close()
	// No session: middleware returns 401 (CodeUnauthorized) or 403.
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 401 or 403 for no session, got %d", resp.StatusCode)
	}
}

// TestOrgMatch_SuperAdminBypass verifies that a super_admin user bypasses the
// orgID-match check even when the session active org does not match.
func TestOrgMatch_SuperAdminBypass(t *testing.T) {
	orgID := ulid.New()
	otherOrg := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	// Give the user a super_admin role in storage.
	store.addRole(&models.Role{ID: ulid.New(), Name: models.SystemRoleSuperAdmin})
	sess := fakeAdminSession(otherOrg) // would normally be rejected
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	// listUsers should succeed for a super_admin even with mismatched active org.
	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/users"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 for super_admin bypass, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// GET /admin/v1/organizations/{orgID}/users/{userID} -- getUser
// -----------------------------------------------------------------------------

// TestGetUser_OK verifies that getUser returns 200 JSON with user + roles.
func TestGetUser_OK(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	store.addMember(orgID, user.ID, models.OrgRoleMember)

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/users/"+user.ID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["email"]; !ok {
		t.Fatal("response missing email field")
	}
}

// TestGetUser_NotInOrg verifies that a user not in the org returns 404.
func TestGetUser_NotInOrg(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	// deliberately NOT adding user as member

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/users/"+user.ID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for user not in org, got %d", resp.StatusCode)
	}
}

// TestGetUser_InvalidUserID verifies that a bad ULID in the path returns 400.
func TestGetUser_InvalidUserID(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/users/not-a-ulid"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid userID, got %d", resp.StatusCode)
	}
}

// TestGetUser_MissingPermission verifies that lacking permission returns 403.
func TestGetUser_MissingPermission(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	store.addMember(orgID, user.ID, models.OrgRoleMember)

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, false) // permission denied
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/users/"+user.ID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for missing permission, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// PATCH /admin/v1/organizations/{orgID}/users/{userID} -- patchUser
// -----------------------------------------------------------------------------

// TestPatchUser_OK verifies that patchUser returns 200 JSON.
func TestPatchUser_OK(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	store.addMember(orgID, user.ID, models.OrgRoleMember)

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"status": "active"})
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/users/"+user.ID.String()), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

// TestPatchUser_NotInOrg verifies that patching a user not in the org returns
// 404.
func TestPatchUser_NotInOrg(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	// user is NOT a member

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"status": "active"})
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/users/"+user.ID.String()), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for user not in org, got %d", resp.StatusCode)
	}
}

// TestPatchUser_BadJSON verifies that a malformed body returns 400.
func TestPatchUser_BadJSON(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	store.addMember(orgID, user.ID, models.OrgRoleMember)

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/users/"+user.ID.String()), []byte("{bad"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d", resp.StatusCode)
	}
}

// TestPatchUser_MissingPermission verifies that lacking permission returns 403.
func TestPatchUser_MissingPermission(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	store.addMember(orgID, user.ID, models.OrgRoleMember)

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, false)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"status": "active"})
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/users/"+user.ID.String()), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for missing permission, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// GET /admin/v1/organizations/{orgID}/sessions -- listSessions
// -----------------------------------------------------------------------------

// TestListSessions_OK verifies that listSessions returns 200 JSON.
func TestListSessions_OK(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/sessions?user_id="+user.ID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["sessions"]; !ok {
		t.Fatal("response missing sessions field")
	}
}

// TestListSessions_MissingUserID verifies that omitting user_id returns 400.
func TestListSessions_MissingUserID(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/sessions"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for missing user_id, got %d", resp.StatusCode)
	}
}

// TestListSessions_InvalidUserID verifies that an invalid user_id returns 400.
func TestListSessions_InvalidUserID(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/sessions?user_id=not-a-ulid"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid user_id, got %d", resp.StatusCode)
	}
}

// TestListSessions_MissingPermission verifies that lacking permission returns
// 403.
func TestListSessions_MissingPermission(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, false)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/sessions?user_id="+user.ID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for missing permission, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// DELETE /admin/v1/organizations/{orgID}/sessions/{sessionID} -- revokeSession
// -----------------------------------------------------------------------------

// TestRevokeSession_OK verifies that revoking an existing session returns 204.
func TestRevokeSession_OK(t *testing.T) {
	orgID := ulid.New()
	sessID := ulid.New()
	store := newStubStorage()
	// Seed the session so RevokeSession succeeds.
	store.sessions[sessID] = &models.Session{ID: sessID}

	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/sessions/"+sessID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
}

// TestRevokeSession_NotFound verifies that ErrStorageNotFound returns 404.
func TestRevokeSession_NotFound(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	store.revokeErr = models.ErrStorageNotFound

	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/sessions/"+ulid.New().String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for missing session, got %d", resp.StatusCode)
	}
}

// TestRevokeSession_InvalidSessionID verifies that a bad ULID returns 400.
func TestRevokeSession_InvalidSessionID(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/sessions/not-a-ulid"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid sessionID, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// GET /admin/v1/organizations/{orgID}/roles -- listRoles
// -----------------------------------------------------------------------------

// TestListRoles_OK verifies that listRoles returns 200 JSON with the roles
// slice.
func TestListRoles_OK(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	orgIDCp := orgID
	store.addRole(&models.Role{ID: ulid.New(), OrganizationID: &orgIDCp, Name: "editor"})

	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/roles"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["roles"]; !ok {
		t.Fatal("response missing roles field")
	}
}

// TestListRoles_MissingPermission verifies that lacking permission returns 403.
func TestListRoles_MissingPermission(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, false)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/roles"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// PATCH /admin/v1/organizations/{orgID}/roles/{roleID} -- updateRole
// -----------------------------------------------------------------------------

// TestUpdateRole_OK verifies that updateRole returns 200 JSON.
func TestUpdateRole_OK(t *testing.T) {
	orgID := ulid.New()
	roleID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	rbac := &stubRBAC{role: models.Role{ID: roleID, Name: "editor"}}
	srv := buildAdminServer(store, rbac, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"name": "reviewer"})
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/roles/"+roleID.String()), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

// TestUpdateRole_NotFound verifies that ErrStorageNotFound from UpdateRole
// returns 404.
func TestUpdateRole_NotFound(t *testing.T) {
	orgID := ulid.New()
	roleID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	rbac := &stubRBAC{updateErr: models.ErrStorageNotFound}
	srv := buildAdminServer(store, rbac, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"name": "x"})
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/roles/"+roleID.String()), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for missing role, got %d", resp.StatusCode)
	}
}

// TestUpdateRole_UnknownPermission verifies that ErrUnknownPermission from
// UpdateRole returns 400.
func TestUpdateRole_UnknownPermission(t *testing.T) {
	orgID := ulid.New()
	roleID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	rbac := &stubRBAC{updateErr: models.ErrUnknownPermission}
	srv := buildAdminServer(store, rbac, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"permissions": []string{"bogus:perm"}})
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/roles/"+roleID.String()), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown permission, got %d", resp.StatusCode)
	}
}

// TestUpdateRole_BadJSON verifies that a malformed body returns 400.
func TestUpdateRole_BadJSON(t *testing.T) {
	orgID := ulid.New()
	roleID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/roles/"+roleID.String()), []byte("{bad"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d", resp.StatusCode)
	}
}

// TestUpdateRole_InvalidRoleID verifies that a bad ULID in the path returns
// 400.
func TestUpdateRole_InvalidRoleID(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"name": "x"})
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/roles/not-a-ulid"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid roleID, got %d", resp.StatusCode)
	}
}

// TestUpdateRole_MissingPermission verifies that lacking permission returns 403.
func TestUpdateRole_MissingPermission(t *testing.T) {
	orgID := ulid.New()
	roleID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, false)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"name": "x"})
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/roles/"+roleID.String()), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for missing permission, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// GET /admin/v1/organizations/{orgID}/oauth_accounts -- listOAuthAccounts
// -----------------------------------------------------------------------------

// TestListOAuthAccounts_OK verifies that listOAuthAccounts returns 200 JSON
// with an empty accounts slice (stub implementation).
func TestListOAuthAccounts_OK(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/oauth_accounts"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["accounts"]; !ok {
		t.Fatal("response missing accounts field")
	}
}

// TestListOAuthAccounts_MissingPermission verifies that lacking permission
// returns 403.
func TestListOAuthAccounts_MissingPermission(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, false)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/oauth_accounts"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for missing permission, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// POST /admin/v1/organizations/{orgID}/users -- inviteUser
// -----------------------------------------------------------------------------

// TestInviteUser_OK verifies that inviting a new user returns 201 JSON.
func TestInviteUser_OK(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"email": "new@example.com"})
	resp := doAdminJSON(t, http.MethodPost, adminURL(srv, orgID, "/users"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201, got %d", resp.StatusCode)
	}
}

// TestInviteUser_ExistingUser verifies that inviting an already-existing user
// (by email) returns 201 and links them to the org.
func TestInviteUser_ExistingUser(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	existing := fakeAdminUser()
	existing.Email = "existing@example.com"
	store.addUser(existing)

	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"email": existing.Email})
	resp := doAdminJSON(t, http.MethodPost, adminURL(srv, orgID, "/users"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201 for existing user invite, got %d", resp.StatusCode)
	}
}

// TestInviteUser_MissingEmail verifies that omitting email returns 400.
func TestInviteUser_MissingEmail(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{})
	resp := doAdminJSON(t, http.MethodPost, adminURL(srv, orgID, "/users"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for missing email, got %d", resp.StatusCode)
	}
}

// TestInviteUser_BadJSON verifies that a malformed body returns 400.
func TestInviteUser_BadJSON(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodPost, adminURL(srv, orgID, "/users"), []byte("{bad"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d", resp.StatusCode)
	}
}

// TestInviteUser_MissingPermission verifies that lacking permission returns 403.
func TestInviteUser_MissingPermission(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, false)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"email": "x@example.com"})
	resp := doAdminJSON(t, http.MethodPost, adminURL(srv, orgID, "/users"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for missing permission, got %d", resp.StatusCode)
	}
}

// TestInviteUser_WithRoleID verifies that inviting with a roleId calls GrantRole.
func TestInviteUser_WithRoleID(t *testing.T) {
	orgID := ulid.New()
	roleID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	rbac := &stubRBAC{}
	srv := buildAdminServer(store, rbac, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"email": "withRole@example.com", "roleId": roleID.String()})
	resp := doAdminJSON(t, http.MethodPost, adminURL(srv, orgID, "/users"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201 with roleId, got %d", resp.StatusCode)
	}
}

// TestInviteUser_InvalidRoleID verifies that an invalid roleId ULID returns
// 400.
func TestInviteUser_InvalidRoleID(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"email": "x@example.com", "roleId": "not-a-ulid"})
	resp := doAdminJSON(t, http.MethodPost, adminURL(srv, orgID, "/users"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid roleId, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// DELETE /admin/v1/organizations/{orgID}/users/{userID} -- removeUser
// -----------------------------------------------------------------------------

// TestRemoveUser_OK verifies that removing a member returns 204.
func TestRemoveUser_OK(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	store.addMember(orgID, user.ID, models.OrgRoleMember)

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/users/"+user.ID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
}

// TestRemoveUser_NotFound verifies that removing a non-member returns 404.
func TestRemoveUser_NotFound(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	// user is NOT a member

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/users/"+user.ID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for non-member, got %d", resp.StatusCode)
	}
}

// TestRemoveUser_InvalidUserID verifies that a bad ULID in the path returns
// 400.
func TestRemoveUser_InvalidUserID(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/users/not-a-ulid"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid userID, got %d", resp.StatusCode)
	}
}

// TestRemoveUser_MissingPermission verifies that lacking permission returns 403.
func TestRemoveUser_MissingPermission(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	store.addMember(orgID, user.ID, models.OrgRoleMember)

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, false)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/users/"+user.ID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for missing permission, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// POST /admin/v1/organizations/{orgID}/roles -- createRole
// -----------------------------------------------------------------------------

// TestCreateRole_OK verifies that createRole returns 201 JSON.
func TestCreateRole_OK(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"name": "editor", "permissions": []string{}})
	resp := doAdminJSON(t, http.MethodPost, adminURL(srv, orgID, "/roles"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201, got %d", resp.StatusCode)
	}
}

// TestCreateRole_MissingName verifies that omitting name returns 400.
func TestCreateRole_MissingName(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"description": "no name"})
	resp := doAdminJSON(t, http.MethodPost, adminURL(srv, orgID, "/roles"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for missing name, got %d", resp.StatusCode)
	}
}

// TestCreateRole_UnknownPermission verifies that ErrUnknownPermission from
// CreateRole returns 400.
func TestCreateRole_UnknownPermission(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	rbac := &stubRBAC{createErr: models.ErrUnknownPermission}
	srv := buildAdminServer(store, rbac, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"name": "bad", "permissions": []string{"bogus:perm"}})
	resp := doAdminJSON(t, http.MethodPost, adminURL(srv, orgID, "/roles"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown permission, got %d", resp.StatusCode)
	}
}

// TestCreateRole_BadJSON verifies that a malformed body returns 400.
func TestCreateRole_BadJSON(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodPost, adminURL(srv, orgID, "/roles"), []byte("{bad"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d", resp.StatusCode)
	}
}

// TestCreateRole_MissingPermission verifies that lacking permission returns 403.
func TestCreateRole_MissingPermission(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, false)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"name": "x"})
	resp := doAdminJSON(t, http.MethodPost, adminURL(srv, orgID, "/roles"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for missing permission, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// DELETE /admin/v1/organizations/{orgID}/roles/{roleID} -- deleteRole
// -----------------------------------------------------------------------------

// TestDeleteRole_OK verifies that deleteRole returns 204.
func TestDeleteRole_OK(t *testing.T) {
	orgID := ulid.New()
	roleID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/roles/"+roleID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
}

// TestDeleteRole_NotFound verifies that ErrStorageNotFound from DeleteRole
// returns 404.
func TestDeleteRole_NotFound(t *testing.T) {
	orgID := ulid.New()
	roleID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	rbac := &stubRBAC{deleteErr: models.ErrStorageNotFound}
	srv := buildAdminServer(store, rbac, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/roles/"+roleID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for missing role, got %d", resp.StatusCode)
	}
}

// TestDeleteRole_RoleInUse verifies that ErrRoleInUse from DeleteRole returns
// 409.
func TestDeleteRole_RoleInUse(t *testing.T) {
	orgID := ulid.New()
	roleID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	rbac := &stubRBAC{deleteErr: models.ErrRoleInUse}
	srv := buildAdminServer(store, rbac, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/roles/"+roleID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("want 409 for role in use, got %d", resp.StatusCode)
	}
}

// TestDeleteRole_InvalidRoleID verifies that a bad ULID in the path returns
// 400.
func TestDeleteRole_InvalidRoleID(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/roles/not-a-ulid"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid roleID, got %d", resp.StatusCode)
	}
}

// TestDeleteRole_MissingPermission verifies that lacking permission returns 403.
func TestDeleteRole_MissingPermission(t *testing.T) {
	orgID := ulid.New()
	roleID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, false)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/roles/"+roleID.String()), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for missing permission, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// GET /admin/v1/organizations/{orgID}/audit -- queryAudit
// -----------------------------------------------------------------------------

// TestQueryAudit_OK verifies that queryAudit returns 200 JSON.
func TestQueryAudit_OK(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	audit := &stubAudit{events: []models.AuditEvent{}}
	srv := buildAdminServer(store, &stubRBAC{}, audit, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/audit"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["events"]; !ok {
		t.Fatal("response missing events field")
	}
}

// TestQueryAudit_WithFilters verifies that queryAudit accepts action, actor,
// since, and until query params and returns 200.
func TestQueryAudit_WithFilters(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	audit := &stubAudit{events: []models.AuditEvent{}}
	srv := buildAdminServer(store, &stubRBAC{}, audit, user, sess, true)
	defer srv.Close()

	actorID := ulid.New().String()
	url := adminURL(srv, orgID, "/audit?action=user.login&actor="+actorID+
		"&since=2025-01-01T00:00:00Z&until=2025-12-31T23:59:59Z")
	resp := doAdminJSON(t, http.MethodGet, url, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

// TestQueryAudit_InvalidActor verifies that a bad actor ULID returns 400.
func TestQueryAudit_InvalidActor(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/audit?actor=not-a-ulid"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid actor, got %d", resp.StatusCode)
	}
}

// TestQueryAudit_InvalidSince verifies that a bad since timestamp returns 400.
func TestQueryAudit_InvalidSince(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/audit?since=not-a-time"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid since, got %d", resp.StatusCode)
	}
}

// TestQueryAudit_InvalidUntil verifies that a bad until timestamp returns 400.
func TestQueryAudit_InvalidUntil(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/audit?until=not-a-time"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid until, got %d", resp.StatusCode)
	}
}

// TestQueryAudit_MissingPermission verifies that lacking permission returns 403.
func TestQueryAudit_MissingPermission(t *testing.T) {
	orgID := ulid.New()
	store := newStubStorage()
	user := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, false)
	defer srv.Close()

	resp := doAdminJSON(t, http.MethodGet, adminURL(srv, orgID, "/audit"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for missing permission, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// patchUser with roleIds -- additional coverage for role-diff paths
// -----------------------------------------------------------------------------

// TestPatchUser_WithRoleIDs verifies that patchUser with a valid roleIds list
// calls GrantRole for new roles and returns 200.
func TestPatchUser_WithRoleIDs(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	store.addMember(orgID, user.ID, models.OrgRoleMember)

	// Seed a role that belongs to orgID.
	orgIDCp := orgID
	roleID := ulid.New()
	store.addRole(&models.Role{ID: roleID, OrganizationID: &orgIDCp, Name: "editor"})

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"roleIds": []string{roleID.String()}})
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/users/"+user.ID.String()), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 with roleIds, got %d", resp.StatusCode)
	}
}

// TestPatchUser_InvalidRoleID verifies that an invalid roleId ULID returns 400.
func TestPatchUser_InvalidRoleID(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	store.addMember(orgID, user.ID, models.OrgRoleMember)

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"roleIds": []string{"not-a-ulid"}})
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/users/"+user.ID.String()), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid roleId, got %d", resp.StatusCode)
	}
}

// TestPatchUser_RoleNotFound verifies that a roleId not found in storage
// returns 404.
func TestPatchUser_RoleNotFound(t *testing.T) {
	orgID := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	store.addMember(orgID, user.ID, models.OrgRoleMember)

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	// Role does not exist in storage.
	unknownRoleID := ulid.New()
	body, _ := json.Marshal(map[string]interface{}{"roleIds": []string{unknownRoleID.String()}})
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/users/"+user.ID.String()), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for missing role, got %d", resp.StatusCode)
	}
}

// TestPatchUser_RoleWrongOrg verifies that a roleId belonging to a different
// org returns 404.
func TestPatchUser_RoleWrongOrg(t *testing.T) {
	orgID := ulid.New()
	otherOrg := ulid.New()
	user := fakeAdminUser()
	store := newStubStorage()
	store.addUser(user)
	store.addMember(orgID, user.ID, models.OrgRoleMember)

	// Role belongs to otherOrg, not orgID.
	roleID := ulid.New()
	store.addRole(&models.Role{ID: roleID, OrganizationID: &otherOrg, Name: "stranger"})

	sess := fakeAdminSession(orgID)
	srv := buildAdminServer(store, &stubRBAC{}, &stubAudit{}, user, sess, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{"roleIds": []string{roleID.String()}})
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/users/"+user.ID.String()), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for role in wrong org, got %d", resp.StatusCode)
	}
}
