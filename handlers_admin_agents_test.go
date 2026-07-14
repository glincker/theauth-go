package theauth_test

import (
	"bytes"
	"crypto/rand"
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

type agentAdminFixture struct {
	server     *httptest.Server
	auth       *theauth.TheAuth
	store      *memory.Store
	orgID      theauth.ULID
	ownerUser  theauth.User
	memberUser theauth.User
	cookieName string
	ownerTok   string
	memberTok  string
}

func newAgentAdminFixture(t *testing.T) agentAdminFixture {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "http://localhost",
		SessionTTL:    time.Hour,
		MagicLinkTTL:  time.Minute,
		EncryptionKey: key,
		RBAC:          &theauth.RBACConfig{},
		Audit:         &theauth.AuditConfig{BufferSize: 256, BatchSize: 16, FlushInterval: 20 * time.Millisecond},
		Admin:         &theauth.AdminConfig{},
		Organizations: &theauth.OrganizationsConfig{},
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			Resources:       []theauth.ProtectedResource{{Identifier: "https://mcp.example.com", Scopes: []string{"read", "write"}}},
			DisableRotation: true,
		},
		AgentIdentity: &theauth.AgentConfig{},
		AccountUX:     true,
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
	roleByName := map[string]theauth.Role{}
	for _, r := range rolesList {
		roleByName[r.Name] = r
	}

	mkUser := func(email string) theauth.User {
		u := theauth.User{ID: internalulid.New(), Email: email}
		u, _ = store.CreateUser(ctx, u)
		if err := store.UpsertOrganizationMember(ctx, theauth.OrganizationMember{OrganizationID: orgID, UserID: u.ID, Role: theauth.OrgRoleMember}); err != nil {
			t.Fatalf("UpsertOrganizationMember: %v", err)
		}
		return u
	}
	owner := mkUser("owner@acme.test")
	member := mkUser("member@acme.test")
	if err := store.GrantUserRole(ctx, theauth.UserRole{UserID: owner.ID, RoleID: roleByName[theauth.OrgRoleOwner].ID}); err != nil {
		t.Fatal(err)
	}
	if err := store.GrantUserRole(ctx, theauth.UserRole{UserID: member.ID, RoleID: roleByName[theauth.OrgRoleMember].ID}); err != nil {
		t.Fatal(err)
	}
	ownerTok, ownerSess, err := theauth.IssueSessionForTest(a, ctx, owner, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	memberTok, memberSess, err := theauth.IssueSessionForTest(a, ctx, member, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	orgPtr := orgID
	_ = store.SetSessionActiveOrganization(ctx, ownerSess.ID, &orgPtr)
	_ = store.SetSessionActiveOrganization(ctx, memberSess.ID, &orgPtr)

	return agentAdminFixture{
		server: srv, auth: a, store: store, orgID: orgID,
		ownerUser: owner, memberUser: member,
		cookieName: "theauth_session",
		ownerTok:   ownerTok, memberTok: memberTok,
	}
}

func (fx agentAdminFixture) do(t *testing.T, method, path, token string, body any) (*http.Response, []byte) {
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

func TestAdminAgents_CreateListPatchDelete(t *testing.T) {
	fx := newAgentAdminFixture(t)
	base := "/admin/v1/organizations/" + fx.orgID.String()

	// Member lacks agents:admin -> 403.
	resp, body := fx.do(t, "POST", base+"/agents", fx.memberTok, map[string]any{"name": "bot1"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member should be forbidden, got %d body=%s", resp.StatusCode, body)
	}

	// Owner creates an agent.
	resp, body = fx.do(t, "POST", base+"/agents", fx.ownerTok, map[string]any{
		"name":  "build-bot",
		"scope": []string{"read"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("owner create want 201, got %d body=%s", resp.StatusCode, body)
	}
	var created struct {
		Agent      theauth.Agent       `json:"agent"`
		Credential theauth.AgentSecret `json:"credential"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}
	if created.Credential.Secret == "" {
		t.Fatalf("expected non-empty credential secret")
	}
	if created.Agent.OrganizationID == nil || *created.Agent.OrganizationID != fx.orgID {
		t.Fatalf("agent owner mismatch: %+v", created.Agent)
	}

	// List sees the agent.
	resp, body = fx.do(t, "GET", base+"/agents", fx.ownerTok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list want 200, got %d body=%s", resp.StatusCode, body)
	}
	var list struct {
		Agents []theauth.Agent `json:"agents"`
	}
	_ = json.Unmarshal(body, &list)
	if len(list.Agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(list.Agents))
	}

	// Patch suspend.
	patchURL := base + "/agents/" + created.Agent.ID.String()
	resp, body = fx.do(t, "PATCH", patchURL, fx.ownerTok, map[string]any{"status": theauth.AgentStatusSuspended, "reason": "test"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch want 200, got %d body=%s", resp.StatusCode, body)
	}

	// Delete (revoke).
	resp, body = fx.do(t, "DELETE", patchURL, fx.ownerTok, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete want 204, got %d body=%s", resp.StatusCode, body)
	}
}

func TestAdminDelegations_CreateAndRevoke(t *testing.T) {
	fx := newAgentAdminFixture(t)
	base := "/admin/v1/organizations/" + fx.orgID.String()

	// Create an agent first.
	agent, _, err := fx.auth.CreateAgent(t.Context(), theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{OrganizationID: &fx.orgID},
		Name:  "deleg-bot",
		Scope: []string{"read"},
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// Create a delegation as owner.
	body := map[string]any{
		"userId":             fx.ownerUser.ID.String(),
		"agentId":            agent.ID.String(),
		"scope":              []string{"read"},
		"resource":           "https://mcp.example.com",
		"maxDurationSeconds": 3600,
	}
	resp, raw := fx.do(t, "POST", base+"/delegations", fx.ownerTok, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create delegation want 201, got %d body=%s", resp.StatusCode, raw)
	}
	var grant theauth.DelegationGrant
	if err := json.Unmarshal(raw, &grant); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// List by user_id filter.
	resp, raw = fx.do(t, "GET", base+"/delegations?user_id="+fx.ownerUser.ID.String(), fx.ownerTok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list want 200, got %d body=%s", resp.StatusCode, raw)
	}

	// Revoke.
	resp, raw = fx.do(t, "DELETE", base+"/delegations/"+grant.ID.String(), fx.ownerTok, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke want 204, got %d body=%s", resp.StatusCode, raw)
	}

	// Confirm RevokedAt is set.
	stored, err := fx.store.DelegationGrantByID(t.Context(), grant.ID)
	if err != nil {
		t.Fatalf("DelegationGrantByID: %v", err)
	}
	if stored.RevokedAt == nil {
		t.Fatalf("expected RevokedAt to be set after admin revoke")
	}
}

// TestAdminCreateDelegation_RejectsNonMemberUser locks in the security
// audit H3 (2026-06-20) regression: an org admin must not be able to
// declare a delegation_grant naming a user who is not a member of the
// calling admin's organization.
func TestAdminCreateDelegation_RejectsNonMemberUser(t *testing.T) {
	fx := newAgentAdminFixture(t)
	base := "/admin/v1/organizations/" + fx.orgID.String()

	// Provision a second user that is NOT a member of fx.orgID.
	outsider := theauth.User{ID: internalulid.New(), Email: "outsider@example.test"}
	outsider, err := fx.store.CreateUser(t.Context(), outsider)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Provision an agent inside fx.orgID so the only authorization gap
	// being exercised is the user-in-org check (not agent ownership).
	agent, _, err := fx.auth.CreateAgent(t.Context(), theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{OrganizationID: &fx.orgID},
		Name:  "deleg-bot-cross",
		Scope: []string{"read"},
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	body := map[string]any{
		"userId":             outsider.ID.String(),
		"agentId":            agent.ID.String(),
		"scope":              []string{"read"},
		"resource":           "https://mcp.example.com",
		"maxDurationSeconds": 3600,
	}
	resp, raw := fx.do(t, "POST", base+"/delegations", fx.ownerTok, body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-org delegation must be 403; got %d body=%s", resp.StatusCode, raw)
	}

	// Member of the org is still permitted (sanity check that the
	// rejection is keyed on membership, not on any other side-effect).
	body["userId"] = fx.memberUser.ID.String()
	resp, raw = fx.do(t, "POST", base+"/delegations", fx.ownerTok, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("in-org delegation must be 201; got %d body=%s", resp.StatusCode, raw)
	}
}

func TestAccountAgents_OwnerOnly(t *testing.T) {
	fx := newAgentAdminFixture(t)

	// Owner user creates a personal agent.
	resp, body := fx.do(t, "POST", "/account/agents", fx.ownerTok, map[string]any{
		"name":  "my-bot",
		"scope": []string{"read"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("account create want 201, got %d body=%s", resp.StatusCode, body)
	}
	var created struct {
		Agent      theauth.Agent       `json:"agent"`
		Credential theauth.AgentSecret `json:"credential"`
	}
	_ = json.Unmarshal(body, &created)
	if created.Agent.OwnerUserID == nil || *created.Agent.OwnerUserID != fx.ownerUser.ID {
		t.Fatalf("expected owner user id %s, got %+v", fx.ownerUser.ID, created.Agent)
	}

	// Member cannot see owner's agents (the list is scoped to caller).
	resp, body = fx.do(t, "GET", "/account/agents", fx.memberTok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member list want 200, got %d body=%s", resp.StatusCode, body)
	}
	var memberList struct {
		Agents []theauth.Agent `json:"agents"`
	}
	_ = json.Unmarshal(body, &memberList)
	if len(memberList.Agents) != 0 {
		t.Fatalf("expected member to see 0 agents, got %d", len(memberList.Agents))
	}

	// Member cannot revoke owner's agent: 404 (no leak).
	resp, body = fx.do(t, "DELETE", "/account/agents/"+created.Agent.ID.String(), fx.memberTok, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-user revoke want 404, got %d body=%s", resp.StatusCode, body)
	}

	// Owner revokes own agent.
	resp, body = fx.do(t, "DELETE", "/account/agents/"+created.Agent.ID.String(), fx.ownerTok, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("owner revoke want 204, got %d body=%s", resp.StatusCode, body)
	}
}

func TestAccountDelegations_CascadeOnRevoke(t *testing.T) {
	fx := newAgentAdminFixture(t)

	uid := fx.ownerUser.ID
	agent, _, err := fx.auth.CreateAgent(t.Context(), theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "my-bot",
		Scope: []string{"read"},
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// Create delegation via /account/delegations as the owner.
	body := map[string]any{
		"agentId":            agent.ID.String(),
		"scope":              []string{"read"},
		"resource":           "https://mcp.example.com",
		"maxDurationSeconds": 3600,
	}
	resp, raw := fx.do(t, "POST", "/account/delegations", fx.ownerTok, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create delegation want 201, got %d body=%s", resp.StatusCode, raw)
	}
	var grant theauth.DelegationGrant
	_ = json.Unmarshal(raw, &grant)

	// Revoke via /account/delegations/{id}/revoke.
	resp, raw = fx.do(t, "POST", "/account/delegations/"+grant.ID.String()+"/revoke", fx.ownerTok, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke want 204, got %d body=%s", resp.StatusCode, raw)
	}

	// Confirm cascade: stored grant has RevokedAt set.
	stored, err := fx.store.DelegationGrantByID(t.Context(), grant.ID)
	if err != nil {
		t.Fatalf("DelegationGrantByID: %v", err)
	}
	if stored.RevokedAt == nil {
		t.Fatalf("expected RevokedAt set")
	}
}
