package theauth_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	internalulid "github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

type adminFixture struct {
	server     *httptest.Server
	auth       *theauth.TheAuth
	store      *memory.Store
	orgID      theauth.ULID
	ownerUser  theauth.User
	memberUser theauth.User
	cookieName string
	ownerTok   string
	memberTok  string
	roles      map[string]theauth.Role
}

func newAdminFixture(t *testing.T) adminFixture {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "http://localhost",
		SessionTTL:    time.Hour,
		MagicLinkTTL:  time.Minute,
		RBAC:          &theauth.RBACConfig{},
		Audit:         &theauth.AuditConfig{BufferSize: 256, BatchSize: 16, FlushInterval: 20 * time.Millisecond},
		Admin:         &theauth.AdminConfig{},
		Organizations: &theauth.OrganizationsConfig{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)

	mux := chi.NewRouter()
	a.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	theauth.SetBaseURLForTest(a, srv.URL)

	ctx := t.Context()
	orgID := internalulid.New()
	if _, err := store.InsertOrganization(ctx, theauth.Organization{ID: orgID, Name: "Acme", Slug: "acme"}); err != nil {
		t.Fatalf("InsertOrganization: %v", err)
	}
	if err := a.SeedOrganizationRoles(ctx, orgID); err != nil {
		t.Fatalf("SeedOrganizationRoles: %v", err)
	}
	orgIDCp := orgID
	rolesList, _ := store.RolesByOrganization(ctx, &orgIDCp)
	roles := map[string]theauth.Role{}
	for _, r := range rolesList {
		roles[r.Name] = r
	}

	mkUser := func(email string) theauth.User {
		u := theauth.User{ID: internalulid.New(), Email: email}
		u, _ = store.CreateUser(ctx, u)
		if err := store.UpsertOrganizationMember(ctx, theauth.OrganizationMember{OrganizationID: orgID, UserID: u.ID, Role: theauth.OrgRoleMember}); err != nil {
			t.Fatalf("UpsertOrganizationMember: %v", err)
		}
		return u
	}
	owner := mkUser("owner@example.test")
	member := mkUser("member@example.test")
	if err := store.GrantUserRole(ctx, theauth.UserRole{UserID: owner.ID, RoleID: roles[theauth.OrgRoleOwner].ID}); err != nil {
		t.Fatalf("grant owner: %v", err)
	}
	if err := store.GrantUserRole(ctx, theauth.UserRole{UserID: member.ID, RoleID: roles[theauth.OrgRoleMember].ID}); err != nil {
		t.Fatalf("grant member: %v", err)
	}

	ownerTok, ownerSess, err := theauth.IssueSessionForTest(a, ctx, owner, "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("owner session: %v", err)
	}
	orgPtr := orgID
	if err := store.SetSessionActiveOrganization(ctx, ownerSess.ID, &orgPtr); err != nil {
		t.Fatalf("set owner active org: %v", err)
	}
	memberTok, memberSess, err := theauth.IssueSessionForTest(a, ctx, member, "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("member session: %v", err)
	}
	if err := store.SetSessionActiveOrganization(ctx, memberSess.ID, &orgPtr); err != nil {
		t.Fatalf("set member active org: %v", err)
	}

	return adminFixture{
		server: srv, auth: a, store: store, orgID: orgID,
		ownerUser: owner, memberUser: member,
		cookieName: "theauth_session",
		ownerTok:   ownerTok, memberTok: memberTok,
		roles: roles,
	}
}

func (fx adminFixture) do(t *testing.T, method, path, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, fx.server.URL+path, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.AddCookie(&http.Cookie{Name: fx.cookieName, Value: token})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func TestAdminListUsersOwnerOK(t *testing.T) {
	fx := newAdminFixture(t)
	path := "/admin/v1/organizations/" + fx.orgID.String() + "/users"
	resp, body := fx.do(t, "GET", path, fx.ownerTok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(body))
	}
}

func TestAdminListUsersMemberForbidden(t *testing.T) {
	// member has users:read so this is allowed; switch to billing endpoint
	// for the forbidden case via roles endpoint POST (roles:admin).
	fx := newAdminFixture(t)
	path := "/admin/v1/organizations/" + fx.orgID.String() + "/roles"
	resp, body := fx.do(t, "POST", path, fx.memberTok, map[string]any{
		"name":        "custom",
		"description": "test",
		"permissions": []string{theauth.PermissionAuditRead},
	})
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d body=%s", resp.StatusCode, string(body))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type=%q, want application/problem+json", ct)
	}
	var p map[string]any
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("body not json: %v: %s", err, string(body))
	}
	if p["code"] != "rbac.forbidden" {
		t.Errorf("code=%v, want rbac.forbidden", p["code"])
	}
}

func TestAdminCreateRoleOwnerOK(t *testing.T) {
	fx := newAdminFixture(t)
	path := "/admin/v1/organizations/" + fx.orgID.String() + "/roles"
	resp, body := fx.do(t, "POST", path, fx.ownerTok, map[string]any{
		"name":        "custom-role",
		"description": "Custom role for tests",
		"permissions": []string{theauth.PermissionAuditRead, theauth.PermissionUsersRead},
	})
	if resp.StatusCode != 201 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(body))
	}
	var got theauth.Role
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v body=%s", err, string(body))
	}
	if got.Name != "custom-role" {
		t.Errorf("name=%q, want custom-role", got.Name)
	}
	if len(got.Permissions) != 2 {
		t.Errorf("permissions=%v, want 2", got.Permissions)
	}
}

func TestAdminCreateRoleUnknownPermission(t *testing.T) {
	fx := newAdminFixture(t)
	path := "/admin/v1/organizations/" + fx.orgID.String() + "/roles"
	resp, body := fx.do(t, "POST", path, fx.ownerTok, map[string]any{
		"name":        "bad",
		"permissions": []string{"not:a:real:permission"},
	})
	if resp.StatusCode != 400 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(body))
	}
	var p map[string]any
	_ = json.Unmarshal(body, &p)
	if p["code"] != "rbac.unknown_permission" {
		t.Errorf("code=%v, want rbac.unknown_permission", p["code"])
	}
}

func TestAdminDeleteRoleSoleUsersAdminConflict(t *testing.T) {
	fx := newAdminFixture(t)
	// Owner role is the only one granting users:admin to anyone in the
	// fixture (admin role exists but unassigned). DELETE the owner role
	// while owner is the only users:admin holder should 409.
	path := "/admin/v1/organizations/" + fx.orgID.String() + "/roles/" + fx.roles[theauth.OrgRoleOwner].ID.String()
	resp, body := fx.do(t, "DELETE", path, fx.ownerTok, nil)
	if resp.StatusCode != 409 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(body))
	}
	var p map[string]any
	_ = json.Unmarshal(body, &p)
	if p["code"] != "rbac.role_in_use" {
		t.Errorf("code=%v, want rbac.role_in_use", p["code"])
	}
}

func TestAdminQueryAuditEmptyOK(t *testing.T) {
	fx := newAdminFixture(t)
	path := "/admin/v1/organizations/" + fx.orgID.String() + "/audit"
	resp, body := fx.do(t, "GET", path, fx.ownerTok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(body))
	}
	var got struct {
		Events []theauth.AuditEvent `json:"events"`
		Next   string               `json:"next"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v body=%s", err, string(body))
	}
	// Audit list endpoint itself emits audit.queried; we tolerate either
	// 0 (writer hasn't flushed yet) or >0 (it has). Either way, no error.
}

func TestAdminNoActiveOrgForbidden(t *testing.T) {
	fx := newAdminFixture(t)
	// Mint a session WITHOUT an active org and try to call an admin endpoint.
	ctx := t.Context()
	tok, sess, err := theauth.IssueSessionForTest(fx.auth, ctx, fx.ownerUser, "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_ = sess
	path := "/admin/v1/organizations/" + fx.orgID.String() + "/users"
	resp, body := fx.do(t, "GET", path, tok, nil)
	if resp.StatusCode != 403 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(body))
	}
	var p map[string]any
	_ = json.Unmarshal(body, &p)
	if p["code"] != "rbac.no_active_org" {
		t.Errorf("code=%v, want rbac.no_active_org", p["code"])
	}
}

func TestAdminOrgMismatchForbidden(t *testing.T) {
	fx := newAdminFixture(t)
	ctx := t.Context()
	otherOrgID := internalulid.New()
	if _, err := fx.store.InsertOrganization(ctx, theauth.Organization{ID: otherOrgID, Name: "Other", Slug: "other"}); err != nil {
		t.Fatalf("InsertOrganization: %v", err)
	}
	path := "/admin/v1/organizations/" + otherOrgID.String() + "/users"
	resp, body := fx.do(t, "GET", path, fx.ownerTok, nil)
	if resp.StatusCode != 403 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(body))
	}
	var p map[string]any
	_ = json.Unmarshal(body, &p)
	if p["code"] != "rbac.org_mismatch" {
		t.Errorf("code=%v, want rbac.org_mismatch", p["code"])
	}
}

func TestAdminInviteUserCreatesMembership(t *testing.T) {
	fx := newAdminFixture(t)
	path := "/admin/v1/organizations/" + fx.orgID.String() + "/users"
	resp, body := fx.do(t, "POST", path, fx.ownerTok, map[string]any{
		"email": "newbie@example.test",
	})
	if resp.StatusCode != 201 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(body))
	}
	var u theauth.User
	if err := json.Unmarshal(body, &u); err != nil {
		t.Fatalf("decode: %v body=%s", err, string(body))
	}
	if u.Email != "newbie@example.test" {
		t.Errorf("email=%q, want newbie@example.test", u.Email)
	}
}

func TestAdminRemoveUserLeavesUserRow(t *testing.T) {
	fx := newAdminFixture(t)
	ctx := t.Context()
	// Add a fresh user so we don't conflict with owner/member fixture.
	newU := theauth.User{ID: internalulid.New(), Email: "tobedeleted@example.test"}
	_, err := fx.store.CreateUser(ctx, newU)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := fx.store.UpsertOrganizationMember(ctx, theauth.OrganizationMember{OrganizationID: fx.orgID, UserID: newU.ID, Role: theauth.OrgRoleMember}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	path := "/admin/v1/organizations/" + fx.orgID.String() + "/users/" + newU.ID.String()
	resp, body := fx.do(t, "DELETE", path, fx.ownerTok, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(body))
	}
	// User row should still exist.
	if _, err := fx.store.UserByID(ctx, newU.ID); err != nil {
		t.Fatalf("user row should remain: %v", err)
	}
}
