package theauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/glincker/theauth-go"
)

// scim_patch_test.go closes the SCIM PATCH branch matrix called out in the
// 2026-06-20 reliability audit (section 2: SCIM PATCH operations). The
// happy-path test in handlers_scim_test.go exercises one attribute path; this
// file enumerates every attribute path supported by applyUserSet /
// applyUserRemove and every branch of applySCIMGroupPatch. The unexported
// helpers are exercised through the live PATCH HTTP endpoint, which means
// these tests also cover the SCIM handler's body decoder, audit emission,
// and storage write path. Both Okta-shaped (path + value object) and
// Azure-AD-shaped (no path, root value object) payloads are tested.

// scimUserPatchFixture wraps newSCIMTestStack with helpers for the per-path
// subtests below. The fixture creates a single user and returns its ID so
// each subtest can issue PATCH operations against it without re-creating
// the row, which keeps the table fast.
type scimUserPatchFixture struct {
	auth    *theauth.TheAuth
	token   string
	srvURL  string
	userID  string
	patchTo func(t *testing.T, ops []map[string]any) (*http.Response, map[string]any)
	getUser func(t *testing.T) map[string]any
}

func newSCIMUserPatchFixture(t *testing.T) *scimUserPatchFixture {
	t.Helper()
	a, _, _, token, srv := newSCIMTestStack(t)
	body := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "patch-user@acme.test",
		"externalId": "ext-original",
		"name":       map[string]string{"givenName": "Alice", "familyName": "Smith", "formatted": "Alice Smith"},
		"emails":     []map[string]any{{"value": "patch-user@acme.test", "primary": true}},
		"active":     true,
	}
	resp := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	var created map[string]any
	decodeBody(t, resp, &created)
	uid := created["id"].(string)
	fx := &scimUserPatchFixture{auth: a, token: token, srvURL: srv.URL, userID: uid}
	fx.patchTo = func(t *testing.T, ops []map[string]any) (*http.Response, map[string]any) {
		t.Helper()
		payload := map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": ops,
		}
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest("PATCH", srv.URL+"/scim/v2/Users/"+uid, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/scim+json")
		r, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Body.Close() }()
		var got map[string]any
		if r.StatusCode == http.StatusOK {
			if jerr := json.NewDecoder(r.Body).Decode(&got); jerr != nil {
				t.Fatalf("decode: %v", jerr)
			}
		}
		return r, got
	}
	fx.getUser = func(t *testing.T) map[string]any {
		t.Helper()
		r := scimReq(t, srv, "GET", "/scim/v2/Users/"+uid, token, nil)
		var got map[string]any
		decodeBody(t, r, &got)
		return got
	}
	return fx
}

// TestApplySCIMUserPatchAllAttributePaths drives a PATCH for every supported
// attribute path (userName, displayName, externalId, name.givenName,
// name.familyName, name.formatted, name object, emails) plus the Azure-AD
// shape (empty path with a value object) plus the unsupported path rejection.
// Each row is a self-contained replace operation; the fixture is rebuilt
// per case to keep field interactions independent.
func TestApplySCIMUserPatchAllAttributePaths(t *testing.T) {
	type assertion struct {
		key  string
		want any
	}
	cases := []struct {
		name       string
		ops        []map[string]any
		wantStatus int
		// assertions are evaluated against the GET response after PATCH.
		// Nested attribute assertions are checked via a "name.givenName"
		// style dot-path resolver below.
		assertions []assertion
	}{
		{
			name: "replace_userName",
			ops: []map[string]any{
				{"op": "replace", "path": "userName", "value": "renamed@acme.test"},
			},
			wantStatus: http.StatusOK,
			assertions: []assertion{{key: "userName", want: "renamed@acme.test"}},
		},
		{
			name: "replace_displayName",
			ops: []map[string]any{
				{"op": "replace", "path": "displayName", "value": "Alice Replacement"},
			},
			wantStatus: http.StatusOK,
			assertions: []assertion{{key: "displayName", want: "Alice Replacement"}},
		},
		{
			name: "replace_externalId",
			ops: []map[string]any{
				{"op": "replace", "path": "externalId", "value": "ext-rotated"},
			},
			wantStatus: http.StatusOK,
			assertions: []assertion{{key: "externalId", want: "ext-rotated"}},
		},
		{
			name: "replace_name_givenName",
			ops: []map[string]any{
				{"op": "replace", "path": "name.givenName", "value": "Alicia"},
			},
			wantStatus: http.StatusOK,
			assertions: []assertion{{key: "name.givenName", want: "Alicia"}},
		},
		{
			name: "replace_name_familyName",
			ops: []map[string]any{
				{"op": "replace", "path": "name.familyName", "value": "Jones"},
			},
			wantStatus: http.StatusOK,
			assertions: []assertion{{key: "name.familyName", want: "Jones"}},
		},
		{
			name: "replace_name_formatted",
			ops: []map[string]any{
				{"op": "replace", "path": "name.formatted", "value": "Alicia Jones"},
			},
			wantStatus: http.StatusOK,
			// name.formatted maps to User.Name (the display blob); the SCIM
			// renderer exposes that as displayName when name.formatted is
			// not echoed back, but the underlying User.Name is what changes.
		},
		{
			name: "replace_name_object",
			ops: []map[string]any{
				{"op": "replace", "path": "name", "value": map[string]any{
					"givenName": "Gwen", "familyName": "Stacey", "formatted": "Gwen Stacey",
				}},
			},
			wantStatus: http.StatusOK,
			assertions: []assertion{
				{key: "name.givenName", want: "Gwen"},
				{key: "name.familyName", want: "Stacey"},
			},
		},
		{
			name: "replace_emails_with_primary",
			ops: []map[string]any{
				{"op": "replace", "path": "emails", "value": []map[string]any{
					{"value": "primary@acme.test", "primary": true},
					{"value": "secondary@acme.test", "primary": false},
				}},
			},
			wantStatus: http.StatusOK,
			assertions: []assertion{{key: "userName", want: "primary@acme.test"}},
		},
		{
			// Azure AD style: no path, value is a root object. The SCIM spec
			// (RFC 7644 section 3.5.2.3) defines this as "merge against the
			// resource"; applyUserSet handles it via the recursive empty-path
			// branch. Active is left true here so the user is not removed
			// from organisation membership (that side effect is asserted in
			// TestApplySCIMUserPatchAzureADDeactivate).
			name: "azure_ad_empty_path_value_object",
			ops: []map[string]any{
				{"op": "replace", "value": map[string]any{
					"displayName": "Updated Via Azure",
					"externalId":  "ext-azure",
				}},
			},
			wantStatus: http.StatusOK,
			assertions: []assertion{
				{key: "displayName", want: "Updated Via Azure"},
				{key: "externalId", want: "ext-azure"},
			},
		},
		{
			name: "add_op_treated_as_set",
			ops: []map[string]any{
				{"op": "add", "path": "displayName", "value": "Added Name"},
			},
			wantStatus: http.StatusOK,
			assertions: []assertion{{key: "displayName", want: "Added Name"}},
		},
		{
			// Unsupported path returns 400 invalidValue. The handler maps
			// ErrUnsupportedFilter to that wire shape.
			name: "unsupported_path_returns_400",
			ops: []map[string]any{
				{"op": "replace", "path": "phoneNumbers[type eq \"work\"].value", "value": "+1-555-0100"},
			},
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newSCIMUserPatchFixture(t)
			resp, body := fx.patchTo(t, tc.ops)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status=%d, want %d, body=%v", resp.StatusCode, tc.wantStatus, body)
			}
			if tc.wantStatus != http.StatusOK {
				return
			}
			got := fx.getUser(t)
			for _, a := range tc.assertions {
				if v := dotLookup(got, a.key); v != a.want {
					t.Errorf("path=%s got=%v want=%v full=%v", a.key, v, a.want, got)
				}
			}
		})
	}
}

// TestApplySCIMUserPatchRemoveBranches covers the remove side of
// applyUserRemove: active, externalId, displayName, and the catch-all
// reject. The active remove path must drop the user from organisation
// membership (the SCIM handler maps active=false to membership removal).
// The displayName remove only clears User.DisplayName; the SCIM wire
// renderer falls back to User.Name (sourced from name.formatted) so
// callers still see a populated displayName field, by design.
func TestApplySCIMUserPatchRemoveBranches(t *testing.T) {
	t.Run("remove_externalId_clears_field", func(t *testing.T) {
		fx := newSCIMUserPatchFixture(t)
		resp, _ := fx.patchTo(t, []map[string]any{{"op": "remove", "path": "externalId"}})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", resp.StatusCode)
		}
		got := fx.getUser(t)
		if v := got["externalId"]; v != nil && v != "" {
			t.Errorf("externalId not cleared, got %v", v)
		}
	})
	t.Run("remove_displayName_clears_underlying_field", func(t *testing.T) {
		// The SCIM renderer falls back to User.Name when DisplayName is
		// empty, so after remove the wire-level displayName equals the
		// fallback. We verify the fallback path is observable by
		// stripping name.formatted via a chained remove and confirming
		// the wire field is now empty. This exercises applyUserRemove's
		// displayName branch as well as the renderer fallback contract.
		fx := newSCIMUserPatchFixture(t)
		// First wipe the underlying name fallback so the fallback chain
		// resolves to empty.
		_, _ = fx.patchTo(t, []map[string]any{
			{"op": "replace", "path": "name.formatted", "value": ""},
		})
		resp, _ := fx.patchTo(t, []map[string]any{{"op": "remove", "path": "displayName"}})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", resp.StatusCode)
		}
		got := fx.getUser(t)
		if v, ok := got["displayName"].(string); ok && v != "" {
			t.Errorf("displayName still populated after both removes: %q", v)
		}
	})
	t.Run("remove_active_returns_200", func(t *testing.T) {
		fx := newSCIMUserPatchFixture(t)
		resp, _ := fx.patchTo(t, []map[string]any{{"op": "remove", "path": "active"}})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", resp.StatusCode)
		}
	})
	t.Run("remove_unsupported_path_returns_400", func(t *testing.T) {
		fx := newSCIMUserPatchFixture(t)
		resp, _ := fx.patchTo(t, []map[string]any{{"op": "remove", "path": "phoneNumbers"}})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", resp.StatusCode)
		}
	})
}

// TestApplySCIMUserPatchUnsupportedOp covers the third branch of the op
// switch in applySCIMUserPatch: anything other than add / replace / remove
// returns ErrUnsupportedFilter which the handler maps to 400.
func TestApplySCIMUserPatchUnsupportedOp(t *testing.T) {
	fx := newSCIMUserPatchFixture(t)
	resp, _ := fx.patchTo(t, []map[string]any{{"op": "move", "path": "displayName", "value": "ignored"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
}

// TestApplySCIMGroupPatchAllBranches enumerates every supported branch of
// applySCIMGroupPatch: displayName replace, externalId replace, members
// add, members remove, members replace (sentinel-clear path), the single
// object form parsed by parseGroupMemberRefs, an empty value rejection,
// and the catch-all unsupported PATCH rejection.
func TestApplySCIMGroupPatchAllBranches(t *testing.T) {
	a, _, _, token, srv := newSCIMTestStack(t)
	_ = a
	createUser := func(email string) string {
		body := map[string]any{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"userName": email,
			"emails":   []map[string]any{{"value": email, "primary": true}},
		}
		r := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
		var got map[string]any
		decodeBody(t, r, &got)
		return got["id"].(string)
	}
	u1 := createUser("ga@acme.test")
	u2 := createUser("gb@acme.test")
	u3 := createUser("gc@acme.test")

	var groupCounter int
	createGroup := func() string {
		groupCounter++
		body := map[string]any{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
			"displayName": "Original-" + ulidStringSuffix(groupCounter),
			"externalId":  "okta-grp-" + ulidStringSuffix(groupCounter),
			"members":     []map[string]any{{"value": u1, "type": "User"}},
		}
		r := scimReq(t, srv, "POST", "/scim/v2/Groups", token, body)
		var got map[string]any
		decodeBody(t, r, &got)
		id, ok := got["id"].(string)
		if !ok {
			t.Fatalf("createGroup: no id in response %v", got)
		}
		return id
	}
	patchGroup := func(t *testing.T, gid string, ops []map[string]any) *http.Response {
		t.Helper()
		payload := map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": ops,
		}
		return scimReq(t, srv, "PATCH", "/scim/v2/Groups/"+gid, token, payload)
	}
	getGroup := func(t *testing.T, gid string) map[string]any {
		t.Helper()
		r := scimReq(t, srv, "GET", "/scim/v2/Groups/"+gid, token, nil)
		var got map[string]any
		decodeBody(t, r, &got)
		return got
	}

	t.Run("displayName_replace", func(t *testing.T) {
		gid := createGroup()
		r := patchGroup(t, gid, []map[string]any{{"op": "replace", "path": "displayName", "value": "Renamed"}})
		defer func() { _ = r.Body.Close() }()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", r.StatusCode)
		}
		got := getGroup(t, gid)
		if got["displayName"] != "Renamed" {
			t.Errorf("displayName=%v, want Renamed", got["displayName"])
		}
	})

	t.Run("externalId_replace", func(t *testing.T) {
		gid := createGroup()
		r := patchGroup(t, gid, []map[string]any{{"op": "replace", "path": "externalId", "value": "okta-grp-rotated"}})
		defer func() { _ = r.Body.Close() }()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", r.StatusCode)
		}
		got := getGroup(t, gid)
		if got["externalId"] != "okta-grp-rotated" {
			t.Errorf("externalId=%v, want okta-grp-rotated", got["externalId"])
		}
	})

	t.Run("members_add_then_remove", func(t *testing.T) {
		gid := createGroup()
		r := patchGroup(t, gid, []map[string]any{
			{"op": "add", "path": "members", "value": []map[string]any{
				{"value": u2, "type": "User"},
				{"value": u3, "type": "User"},
			}},
		})
		_ = r.Body.Close()
		got := getGroup(t, gid)
		if n := membersLen(got); n != 3 {
			t.Fatalf("after add: members=%d, want 3", n)
		}
		r2 := patchGroup(t, gid, []map[string]any{
			{"op": "remove", "path": "members", "value": []map[string]any{
				{"value": u2, "type": "User"},
			}},
		})
		_ = r2.Body.Close()
		got2 := getGroup(t, gid)
		if n := membersLen(got2); n != 2 {
			t.Fatalf("after remove: members=%d, want 2", n)
		}
	})

	t.Run("members_replace_clears_then_sets", func(t *testing.T) {
		gid := createGroup()
		// Pre-load with u1 + u2 so we can observe the replace truly clearing.
		r0 := patchGroup(t, gid, []map[string]any{{"op": "add", "path": "members", "value": []map[string]any{{"value": u2, "type": "User"}}}})
		_ = r0.Body.Close()
		r := patchGroup(t, gid, []map[string]any{
			{"op": "replace", "path": "members", "value": []map[string]any{
				{"value": u3, "type": "User"},
			}},
		})
		defer func() { _ = r.Body.Close() }()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", r.StatusCode)
		}
		got := getGroup(t, gid)
		if n := membersLen(got); n != 1 {
			t.Fatalf("after replace: members=%d, want 1", n)
		}
		members := got["members"].([]any)
		got0 := members[0].(map[string]any)
		if got0["value"] != u3 {
			t.Errorf("after replace: member=%v, want %v", got0["value"], u3)
		}
	})

	t.Run("members_add_single_object_form", func(t *testing.T) {
		// Azure AD frequently sends a single object as the value instead of
		// an array. parseGroupMemberRefs must accept both shapes.
		gid := createGroup()
		r := patchGroup(t, gid, []map[string]any{
			{"op": "add", "path": "members", "value": map[string]any{"value": u2, "type": "User"}},
		})
		defer func() { _ = r.Body.Close() }()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", r.StatusCode)
		}
		got := getGroup(t, gid)
		if n := membersLen(got); n != 2 {
			t.Fatalf("members=%d, want 2", n)
		}
	})

	t.Run("members_empty_value_rejected", func(t *testing.T) {
		gid := createGroup()
		// raw JSON null as value triggers the len(raw) == 0 guard in
		// parseGroupMemberRefs once the handler routes it through.
		body := []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members"}]}`)
		req, _ := http.NewRequest("PATCH", srv.URL+"/scim/v2/Groups/"+gid, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/scim+json")
		r, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Body.Close() }()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", r.StatusCode)
		}
	})

	t.Run("unsupported_patch_rejected", func(t *testing.T) {
		gid := createGroup()
		r := patchGroup(t, gid, []map[string]any{{"op": "replace", "path": "phoneNumbers", "value": "x"}})
		defer func() { _ = r.Body.Close() }()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", r.StatusCode)
		}
	})

	t.Run("nested_group_member_rejected", func(t *testing.T) {
		gid := createGroup()
		r := patchGroup(t, gid, []map[string]any{
			{"op": "add", "path": "members", "value": []map[string]any{
				{"value": "01H00000000000000000000000", "type": "Group"},
			}},
		})
		defer func() { _ = r.Body.Close() }()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", r.StatusCode)
		}
	})

	t.Run("invalid_member_ulid_rejected", func(t *testing.T) {
		gid := createGroup()
		r := patchGroup(t, gid, []map[string]any{
			{"op": "add", "path": "members", "value": []map[string]any{
				{"value": "not-a-real-ulid", "type": "User"},
			}},
		})
		defer func() { _ = r.Body.Close() }()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", r.StatusCode)
		}
	})
}

// TestApplySCIMUserPatchAzureADDeactivate covers the most common Azure-AD
// SCIM shape: a PATCH with no path and a value object containing active
// false. This goes through the empty-path recursion in applyUserSet, then
// the active branch, then the handler's membership-removal side effect.
// Pulled out as its own test so the assertion on organisation membership
// removal is unambiguous.
func TestApplySCIMUserPatchAzureADDeactivate(t *testing.T) {
	a, _, org, token, srv := newSCIMTestStack(t)
	body := map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "azure-deact@acme.test",
		"emails":   []map[string]any{{"value": "azure-deact@acme.test", "primary": true}},
	}
	c := scimReq(t, srv, "POST", "/scim/v2/Users", token, body)
	var created map[string]any
	decodeBody(t, c, &created)
	uid := created["id"].(string)
	patch := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "replace", "value": map[string]any{"active": false}},
		},
	}
	r := scimReq(t, srv, "PATCH", "/scim/v2/Users/"+uid, token, patch)
	defer func() { _ = r.Body.Close() }()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", r.StatusCode)
	}
	members, _ := a.ListOrganizationMembers(context.Background(), org.ID)
	for _, m := range members {
		if m.UserID.String() == uid {
			t.Fatal("user still a member after azure-ad deactivate")
		}
	}
}

// ulidStringSuffix returns a short numeric suffix used to disambiguate
// per-subtest displayName / externalId values so they do not collide on
// the unique constraints.
func ulidStringSuffix(i int) string {
	return strings.Repeat("0", 2) + string(rune('0'+(i%10)))
}

// membersLen returns the count of members on a SCIM group resource map.
// The wire shape uses `omitempty` on members, so an empty group has no
// members key; this helper normalises both shapes to a count.
func membersLen(group map[string]any) int {
	v, ok := group["members"]
	if !ok || v == nil {
		return 0
	}
	arr, ok := v.([]any)
	if !ok {
		return 0
	}
	return len(arr)
}

// dotLookup resolves a dotted key path (e.g. "name.givenName") against a
// nested map[string]any. Returns nil when any segment is missing or not a
// map.
func dotLookup(m map[string]any, key string) any {
	parts := strings.Split(key, ".")
	cur := any(m)
	for _, p := range parts {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = obj[p]
		if !ok {
			return nil
		}
	}
	return cur
}
