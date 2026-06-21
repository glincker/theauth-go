package theauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

func newSCIMTestStack(t *testing.T) (*theauth.TheAuth, *memory.Store, theauth.Organization, string, *httptest.Server) {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://scim.example.test",
		Organizations: &theauth.OrganizationsConfig{},
		SCIM:          &theauth.SCIMConfig{RequireHTTPS: false, MaxPageSize: 200},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	owner := newUser(t, store, "scim-owner@x.test")
	org, err := a.CreateOrganization(context.Background(), "Acme", "acme", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := a.CreateSCIMToken(context.Background(), org.ID, "Okta Production")
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return a, store, org, token, srv
}

// scimPost is a small helper that wraps the bearer header + content-type
// boilerplate for the test stack.
func scimReq(t *testing.T, srv *httptest.Server, method, path, token string, body interface{}) *http.Response {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	var bodyReader interface{ Read(p []byte) (int, error) }
	if rdr != nil {
		bodyReader = rdr
	}
	var req *http.Request
	if bodyReader != nil {
		r, err := http.NewRequest(method, srv.URL+path, bodyReader.(*bytes.Reader))
		if err != nil {
			t.Fatal(err)
		}
		req = r
	} else {
		r, err := http.NewRequest(method, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req = r
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func decodeBody(t *testing.T, r *http.Response, into interface{}) {
	t.Helper()
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(into); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestSCIM_RequiresBearer(t *testing.T) {
	_, _, _, _, srv := newSCIMTestStack(t)
	resp := scimReq(t, srv, "GET", "/scim/v2/Users", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestSCIM_RejectsInvalidToken(t *testing.T) {
	_, _, _, _, srv := newSCIMTestStack(t)
	resp := scimReq(t, srv, "GET", "/scim/v2/Users", "not-a-real-token", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestSCIM_RejectsRevokedToken(t *testing.T) {
	a, _, org, token, srv := newSCIMTestStack(t)
	tokens, _ := a.ListSCIMTokens(context.Background(), org.ID)
	if err := a.RevokeSCIMToken(context.Background(), tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	resp := scimReq(t, srv, "GET", "/scim/v2/Users", token, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestSCIM_CreateUserOkta(t *testing.T) {
	_, _, _, token, srv := newSCIMTestStack(t)
	body := map[string]interface{}{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "alice@acme.test",
		"externalId": "okta-abc-123",
		"name":       map[string]string{"givenName": "Alice", "familyName": "Smith", "formatted": "Alice Smith"},
		"emails":     []map[string]interface{}{{"value": "alice@acme.test", "type": "work", "primary": true}},
		"active":     true,
	}
	resp := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	if resp.StatusCode != http.StatusCreated {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		resp.Body.Close()
		t.Fatalf("want 201, got %d: %s", resp.StatusCode, buf.String())
	}
	var got map[string]interface{}
	decodeBody(t, resp, &got)
	if got["userName"] != "alice@acme.test" {
		t.Fatalf("userName mismatch: %v", got["userName"])
	}
	if got["id"] == "" {
		t.Fatal("missing id")
	}
}

func TestSCIM_UpsertByExternalID(t *testing.T) {
	_, _, _, token, srv := newSCIMTestStack(t)
	body := map[string]interface{}{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "bob@acme.test",
		"externalId": "okta-bob-1",
		"emails":     []map[string]interface{}{{"value": "bob@acme.test", "type": "work", "primary": true}},
	}
	r1 := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	var first map[string]interface{}
	decodeBody(t, r1, &first)
	r2 := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("want 200 on idempotent re-post, got %d", r2.StatusCode)
	}
	var second map[string]interface{}
	decodeBody(t, r2, &second)
	if first["id"] != second["id"] {
		t.Fatalf("id changed across idempotent calls: %v != %v", first["id"], second["id"])
	}
}

func TestSCIM_ListAndPaginate(t *testing.T) {
	_, _, _, token, srv := newSCIMTestStack(t)
	for i := 0; i < 3; i++ {
		body := map[string]interface{}{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"userName": fmt.Sprintf("u%d@acme.test", i),
			"emails":   []map[string]interface{}{{"value": fmt.Sprintf("u%d@acme.test", i), "primary": true}},
		}
		r := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
		r.Body.Close()
	}
	resp := scimReq(t, srv, "GET", "/scim/v2/Users?startIndex=1&count=2", token, nil)
	defer resp.Body.Close()
	var got map[string]interface{}
	decodeBody(t, resp, &got)
	// 3 SCIM-created users + 1 owner = 4 members.
	if int(got["totalResults"].(float64)) != 4 {
		t.Fatalf("totalResults: %v", got["totalResults"])
	}
	if got["Resources"] == nil {
		t.Fatal("no Resources")
	}
}

func TestSCIM_FilterByUserName(t *testing.T) {
	_, _, _, token, srv := newSCIMTestStack(t)
	body := map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "find-me@acme.test",
		"emails":   []map[string]interface{}{{"value": "find-me@acme.test", "primary": true}},
	}
	r := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	r.Body.Close()
	resp := scimReq(t, srv, "GET", `/scim/v2/Users?filter=userName%20eq%20%22find-me@acme.test%22`, token, nil)
	defer resp.Body.Close()
	var got map[string]interface{}
	decodeBody(t, resp, &got)
	if int(got["totalResults"].(float64)) != 1 {
		t.Fatalf("totalResults: %v", got["totalResults"])
	}
}

func TestSCIM_PutReturns405(t *testing.T) {
	_, _, _, token, srv := newSCIMTestStack(t)
	body := map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "p@acme.test",
		"emails":   []map[string]interface{}{{"value": "p@acme.test", "primary": true}},
	}
	c := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	var created map[string]interface{}
	decodeBody(t, c, &created)
	id := created["id"].(string)
	resp := scimReq(t, srv, "PUT", "/scim/v2/Users/"+id, token, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", resp.StatusCode)
	}
}

func TestSCIM_RejectsPassword(t *testing.T) {
	_, _, _, token, srv := newSCIMTestStack(t)
	body := map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "p@acme.test",
		"password": "hunter2",
		"emails":   []map[string]interface{}{{"value": "p@acme.test", "primary": true}},
	}
	resp := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

func TestSCIM_PatchReplace(t *testing.T) {
	_, _, _, token, srv := newSCIMTestStack(t)
	body := map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "patch@acme.test",
		"name":     map[string]string{"givenName": "Old"},
		"emails":   []map[string]interface{}{{"value": "patch@acme.test", "primary": true}},
	}
	c := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	var created map[string]interface{}
	decodeBody(t, c, &created)
	patch := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "name.givenName", "value": "Alicia"},
		},
	}
	resp := scimReq(t, srv, "PATCH", "/scim/v2/Users/"+created["id"].(string), token, patch)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var got map[string]interface{}
	decodeBody(t, resp, &got)
	name := got["name"].(map[string]interface{})
	if name["givenName"] != "Alicia" {
		t.Fatalf("givenName not updated: %v", name)
	}
}

func TestSCIM_DeactivateRemovesMembership(t *testing.T) {
	a, _, org, token, srv := newSCIMTestStack(t)
	body := map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "deact@acme.test",
		"emails":   []map[string]interface{}{{"value": "deact@acme.test", "primary": true}},
	}
	c := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	var created map[string]interface{}
	decodeBody(t, c, &created)
	uid := created["id"].(string)
	patch := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "active", "value": false},
		},
	}
	r := scimReq(t, srv, "PATCH", "/scim/v2/Users/"+uid, token, patch)
	r.Body.Close()
	// user should no longer be in org membership
	members, _ := a.ListOrganizationMembers(context.Background(), org.ID)
	for _, m := range members {
		if m.UserID.String() == uid {
			t.Fatalf("user still a member after deactivation")
		}
	}
}

func TestSCIM_DeleteSoftDeletesMembership(t *testing.T) {
	a, store, org, token, srv := newSCIMTestStack(t)
	body := map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "del@acme.test",
		"emails":   []map[string]interface{}{{"value": "del@acme.test", "primary": true}},
	}
	c := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	var created map[string]interface{}
	decodeBody(t, c, &created)
	uid := created["id"].(string)
	d := scimReq(t, srv, "DELETE", "/scim/v2/Users/"+uid, token, nil)
	if d.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204, got %d", d.StatusCode)
	}
	// Membership gone; underlying user row still present.
	members, _ := a.ListOrganizationMembers(context.Background(), org.ID)
	for _, m := range members {
		if m.UserID.String() == uid {
			t.Fatal("membership not removed")
		}
	}
	if u, _ := store.UserByEmail(context.Background(), "del@acme.test"); u == nil {
		t.Fatal("user row was deleted; should have been preserved")
	}
}

func TestSCIM_GroupsCreatePatchMembers(t *testing.T) {
	_, _, _, token, srv := newSCIMTestStack(t)
	// Seed two users so the group has something to hold.
	createUser := func(email string) string {
		body := map[string]interface{}{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"userName": email,
			"emails":   []map[string]interface{}{{"value": email, "primary": true}},
		}
		r := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
		var got map[string]interface{}
		decodeBody(t, r, &got)
		return got["id"].(string)
	}
	u1 := createUser("g1@acme.test")
	u2 := createUser("g2@acme.test")

	create := map[string]interface{}{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Engineers",
		"externalId":  "okta-grp-1",
		"members":     []map[string]interface{}{{"value": u1, "type": "User"}},
	}
	r := scimReq(t, srv, "POST", "/scim/v2/Groups", token, create)
	if r.StatusCode != http.StatusCreated {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		t.Fatalf("want 201, got %d: %s", r.StatusCode, buf.String())
	}
	var g map[string]interface{}
	decodeBody(t, r, &g)
	gid := g["id"].(string)

	patch := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{
			{"op": "add", "path": "members", "value": []map[string]interface{}{{"value": u2, "type": "User"}}},
		},
	}
	r2 := scimReq(t, srv, "PATCH", "/scim/v2/Groups/"+gid, token, patch)
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", r2.StatusCode)
	}
	get := scimReq(t, srv, "GET", "/scim/v2/Groups/"+gid, token, nil)
	var after map[string]interface{}
	decodeBody(t, get, &after)
	if got := len(after["members"].([]interface{})); got != 2 {
		t.Fatalf("expected 2 members, got %d", got)
	}
}

func TestSCIM_GroupsRejectNested(t *testing.T) {
	_, _, _, token, srv := newSCIMTestStack(t)
	body := map[string]interface{}{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Nested",
		"members":     []map[string]interface{}{{"value": "01H00000000000000000000000", "type": "Group"}},
	}
	resp := scimReq(t, srv, "POST", "/scim/v2/Groups", token, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

func TestSCIM_Discovery(t *testing.T) {
	_, _, _, token, srv := newSCIMTestStack(t)
	for _, p := range []string{"/scim/v2/ServiceProviderConfig", "/scim/v2/ResourceTypes", "/scim/v2/ResourceTypes/User", "/scim/v2/ResourceTypes/Group", "/scim/v2/Schemas"} {
		r := scimReq(t, srv, "GET", p, token, nil)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("%s want 200, got %d", p, r.StatusCode)
		}
		r.Body.Close()
	}
	r := scimReq(t, srv, "GET", "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", token, nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("schema by id want 200, got %d", r.StatusCode)
	}
	defer r.Body.Close()
	var got map[string]interface{}
	decodeBody(t, r, &got)
	if !strings.Contains(got["id"].(string), "User") {
		t.Fatalf("unexpected schema id: %v", got["id"])
	}
}

func TestSCIM_RequiresHTTPS(t *testing.T) {
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://scim.example.test",
		Organizations: &theauth.OrganizationsConfig{},
		SCIM:          &theauth.SCIMConfig{RequireHTTPS: true, MaxPageSize: 200},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	owner := newUser(t, store, "https-owner@x.test")
	org, _ := a.CreateOrganization(context.Background(), "Acme", "acme", owner.ID)
	token, _, _ := a.CreateSCIMToken(context.Background(), org.ID, "t")
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	defer srv.Close()
	resp := scimReq(t, srv, "GET", "/scim/v2/Users", token, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

func TestSCIM_ProvisioningCycle(t *testing.T) {
	a, _, org, token, srv := newSCIMTestStack(t)
	// 1. POST user with externalId
	body := map[string]interface{}{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "cycle@acme.test",
		"externalId": "okta-cycle-1",
		"name":       map[string]string{"givenName": "Cy", "familyName": "Cle"},
		"emails":     []map[string]interface{}{{"value": "cycle@acme.test", "primary": true}},
	}
	c := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	if c.StatusCode != http.StatusCreated {
		t.Fatalf("create want 201, got %d", c.StatusCode)
	}
	var created map[string]interface{}
	decodeBody(t, c, &created)
	uid := created["id"].(string)

	// 2. PATCH name
	patch := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "name.givenName", "value": "Cyclic"},
		},
	}
	p := scimReq(t, srv, "PATCH", "/scim/v2/Users/"+uid, token, patch)
	if p.StatusCode != http.StatusOK {
		t.Fatalf("patch want 200, got %d", p.StatusCode)
	}
	p.Body.Close()

	// 3. PATCH active=false -> removes membership
	deact := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "active", "value": false},
		},
	}
	d := scimReq(t, srv, "PATCH", "/scim/v2/Users/"+uid, token, deact)
	d.Body.Close()
	_ = a
	_ = org

	// 4. POST again with same externalId -> 200 + re-add to org
	re := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	if re.StatusCode != http.StatusOK {
		t.Fatalf("re-create want 200, got %d", re.StatusCode)
	}
	re.Body.Close()

	// 5. DELETE -> 204
	del := scimReq(t, srv, "DELETE", "/scim/v2/Users/"+uid, token, nil)
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete want 204, got %d", del.StatusCode)
	}

	// 6. GET -> 404
	get := scimReq(t, srv, "GET", "/scim/v2/Users/"+uid, token, nil)
	if get.StatusCode != http.StatusNotFound {
		t.Fatalf("get after delete want 404, got %d", get.StatusCode)
	}
}
