package storagetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

// EnterpriseSuiteStorage is the storage RunEnterprise needs.
type EnterpriseSuiteStorage interface {
	theauth.UserStorage
	theauth.SessionStorage
	theauth.OrganizationStorage
	theauth.SAMLStorage
	theauth.SCIMStorage
	theauth.RBACStorage
}

// RunEnterprise runs the organization, SAML, SCIM and organization-scoped
// RBAC contract tests. Pass a fresh storage instance.
func RunEnterprise(t *testing.T, store EnterpriseSuiteStorage) {
	t.Helper()
	t.Run("Organizations", func(t *testing.T) { testOrganizations(t, store) })
	t.Run("SAML", func(t *testing.T) { testSAML(t, store) })
	t.Run("SCIM", func(t *testing.T) { testSCIM(t, store) })
	t.Run("OrgScopedRBAC", func(t *testing.T) { testOrgScopedRBAC(t, store) })
}

// RunEnterpriseConstraints runs the schema-level checks a relational adapter
// must enforce (CHECK, foreign keys, partial unique indexes, cascades). The
// in-memory adapter is looser by design and does not run it.
func RunEnterpriseConstraints(t *testing.T, store EnterpriseSuiteStorage) {
	t.Helper()
	ctx := context.Background()
	user := mustUser(t, store, "constraints-user@storagetest.example")
	org := mustOrg(t, store, "constraints-corp")

	t.Run("UnknownMemberRoleRejected", func(t *testing.T) {
		err := store.UpsertOrganizationMember(ctx, theauth.OrganizationMember{OrganizationID: org.ID, UserID: user.ID, Role: "superuser"})
		if err == nil {
			t.Fatal("unknown member role was accepted")
		}
	})
	t.Run("DuplicateGroupExternalIDRejected", func(t *testing.T) {
		now := time.Now()
		if _, err := store.InsertGroup(ctx, theauth.Group{ID: newID(), OrganizationID: org.ID, DisplayName: "A", ExternalID: "dup", CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.InsertGroup(ctx, theauth.Group{ID: newID(), OrganizationID: org.ID, DisplayName: "B", ExternalID: "dup", CreatedAt: now}); err == nil {
			t.Fatal("duplicate external id in one organization was accepted")
		}
	})
	t.Run("RoleForUnknownOrganizationRejected", func(t *testing.T) {
		unknown := newID()
		if _, err := store.InsertRole(ctx, theauth.Role{ID: newID(), OrganizationID: &unknown, Name: "ghost", CreatedAt: time.Now()}); err == nil {
			t.Fatal("role for an unknown organization was accepted")
		}
	})
	t.Run("OrganizationDeleteRemovesRoles", func(t *testing.T) {
		doomed := mustOrg(t, store, "constraints-doomed")
		role, err := store.InsertRole(ctx, theauth.Role{ID: newID(), OrganizationID: &doomed.ID, Name: "temp", CreatedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteOrganization(ctx, doomed.ID); err != nil {
			t.Fatal(err)
		}
		_, err = store.RoleByID(ctx, role.ID)
		wantNotFound(t, "role after organization delete", err)
	})
}

func mustUser(t *testing.T, s theauth.UserStorage, email string) theauth.User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), theauth.User{ID: newID(), Email: email, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", email, err)
	}
	return u
}

func mustOrg(t *testing.T, s theauth.OrganizationStorage, slug string) theauth.Organization {
	t.Helper()
	now := time.Now()
	o, err := s.InsertOrganization(context.Background(), theauth.Organization{
		ID: newID(), Name: "Org " + slug, Slug: slug, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("InsertOrganization(%s): %v", slug, err)
	}
	return o
}

func mustMember(t *testing.T, s theauth.OrganizationStorage, org, user theauth.ULID, role string) {
	t.Helper()
	if err := s.UpsertOrganizationMember(context.Background(), theauth.OrganizationMember{
		OrganizationID: org, UserID: user, Role: role, JoinedAt: time.Now(),
	}); err != nil {
		t.Fatalf("UpsertOrganizationMember: %v", err)
	}
}

func wantNotFound(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("%s: want ErrNotFound, got %v", what, err)
	}
}

func testOrganizations(t *testing.T, s EnterpriseSuiteStorage) {
	ctx := context.Background()
	owner := mustUser(t, s, "org-owner@storagetest.example")
	member := mustUser(t, s, "org-member@storagetest.example")
	org := mustOrg(t, s, "Acme-Corp")

	t.Run("SlugIsLowercasedAndLookupFolds", func(t *testing.T) {
		if org.Slug != "acme-corp" {
			t.Fatalf("slug = %q, want acme-corp", org.Slug)
		}
		got, err := s.OrganizationBySlug(ctx, "ACME-CORP")
		if err != nil || got.ID != org.ID {
			t.Fatalf("OrganizationBySlug = %v, %v", got, err)
		}
		if _, err := s.OrganizationBySlug(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("missing slug: %v", err)
		}
		if _, err := s.OrganizationByID(ctx, newID()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("missing id: %v", err)
		}
	})

	t.Run("DuplicateSlugRejected", func(t *testing.T) {
		_, err := s.InsertOrganization(ctx, theauth.Organization{ID: newID(), Name: "x", Slug: "ACME-corp", CreatedAt: time.Now()})
		if !errors.Is(err, theauth.ErrSlugTaken) {
			t.Fatalf("want ErrSlugTaken, got %v", err)
		}
		other := mustOrg(t, s, "other-corp")
		other.Slug = "Acme-Corp"
		if err := s.UpdateOrganization(ctx, other); !errors.Is(err, theauth.ErrSlugTaken) {
			t.Fatalf("update to taken slug: want ErrSlugTaken, got %v", err)
		}
	})

	t.Run("UpdateAndMissing", func(t *testing.T) {
		org.Name = "Acme Renamed"
		if err := s.UpdateOrganization(ctx, org); err != nil {
			t.Fatalf("UpdateOrganization: %v", err)
		}
		got, _ := s.OrganizationByID(ctx, org.ID)
		if got == nil || got.Name != "Acme Renamed" {
			t.Fatalf("after update: %+v", got)
		}
		ghost := theauth.Organization{ID: newID(), Name: "g", Slug: "ghost"}
		wantNotFound(t, "update missing", s.UpdateOrganization(ctx, ghost))
		wantNotFound(t, "delete missing", s.DeleteOrganization(ctx, newID()))
	})

	t.Run("Members", func(t *testing.T) {
		mustMember(t, s, org.ID, owner.ID, "owner")
		mustMember(t, s, org.ID, member.ID, "member")
		mustMember(t, s, org.ID, member.ID, "admin") // upsert changes the role
		role, err := s.OrganizationMemberRole(ctx, org.ID, member.ID)
		if err != nil || role != "admin" {
			t.Fatalf("role = %q, %v", role, err)
		}
		list, err := s.OrganizationMembersByOrg(ctx, org.ID)
		if err != nil || len(list) != 2 {
			t.Fatalf("members = %d, %v", len(list), err)
		}
		orgs, err := s.OrganizationsByUser(ctx, member.ID)
		if err != nil || len(orgs) != 1 || orgs[0].ID != org.ID {
			t.Fatalf("OrganizationsByUser = %v, %v", orgs, err)
		}
		stranger := mustUser(t, s, "org-stranger@storagetest.example")
		_, err = s.OrganizationMemberRole(ctx, org.ID, stranger.ID)
		wantNotFound(t, "non-member role", err)
		if err := s.UpsertOrganizationMember(ctx, theauth.OrganizationMember{OrganizationID: newID(), UserID: owner.ID, Role: "member"}); err == nil {
			t.Fatal("membership in an unknown organization was accepted")
		}
		if err := s.DeleteOrganizationMember(ctx, org.ID, member.ID); err != nil {
			t.Fatalf("DeleteOrganizationMember: %v", err)
		}
		wantNotFound(t, "second member delete", s.DeleteOrganizationMember(ctx, org.ID, member.ID))
	})

	t.Run("ActiveOrganizationClearedOnDelete", func(t *testing.T) {
		doomed := mustOrg(t, s, "doomed-corp")
		mustMember(t, s, doomed.ID, owner.ID, "owner")
		sess, err := s.CreateSession(ctx, theauth.Session{
			ID: newID(), UserID: owner.ID, TokenHash: sha256Hash([]byte(fmt.Sprint(newID()))),
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		})
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if err := s.SetSessionActiveOrganization(ctx, sess.ID, &doomed.ID); err != nil {
			t.Fatalf("SetSessionActiveOrganization: %v", err)
		}
		got, err := s.SessionByID(ctx, sess.ID)
		if err != nil || got.ActiveOrganizationID == nil || *got.ActiveOrganizationID != doomed.ID {
			t.Fatalf("active org after set = %+v, %v", got, err)
		}
		if err := s.SetSessionActiveOrganization(ctx, sess.ID, nil); err != nil {
			t.Fatalf("clear: %v", err)
		}
		if got, _ = s.SessionByID(ctx, sess.ID); got.ActiveOrganizationID != nil {
			t.Fatalf("active org after clear = %v", got.ActiveOrganizationID)
		}
		wantNotFound(t, "unknown session", s.SetSessionActiveOrganization(ctx, newID(), &doomed.ID))
		if err := s.SetSessionActiveOrganization(ctx, sess.ID, &doomed.ID); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteOrganization(ctx, doomed.ID); err != nil {
			t.Fatalf("DeleteOrganization: %v", err)
		}
		got, err = s.SessionByID(ctx, sess.ID)
		if err != nil || got.ActiveOrganizationID != nil || got.RevokedAt != nil {
			t.Fatalf("session after org delete = %+v, %v", got, err)
		}
		if orgs, _ := s.OrganizationsByUser(ctx, owner.ID); len(orgs) != 1 {
			t.Fatalf("membership survived org delete: %d orgs", len(orgs))
		}
	})
}

func testSAML(t *testing.T, s EnterpriseSuiteStorage) {
	ctx := context.Background()
	org := mustOrg(t, s, "saml-corp")
	user := mustUser(t, s, "saml-user@storagetest.example")
	now := time.Now()
	am := theauth.DefaultSAMLAttributeMap()
	am.Extra = map[string]string{"dept": "department"}

	conn, err := s.InsertSAMLConnection(ctx, theauth.SAMLConnection{
		ID: newID(), OrganizationID: org.ID, IdPEntityID: "https://idp.example/meta",
		IdPSSOURL: "https://idp.example/sso", IdPX509Cert: "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----",
		SPEntityID: "https://sp.example/meta", SPACSURL: "https://sp.example/acs", AttributeMap: am,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("InsertSAMLConnection: %v", err)
	}

	t.Run("RoundTrip", func(t *testing.T) {
		got, err := s.SAMLConnectionByID(ctx, conn.ID)
		if err != nil {
			t.Fatalf("SAMLConnectionByID: %v", err)
		}
		if got.IdPEntityID != conn.IdPEntityID || got.AttributeMap.Email != am.Email || got.AttributeMap.Extra["dept"] != "department" {
			t.Fatalf("round trip mismatch: %+v", got)
		}
		list, err := s.SAMLConnectionsByOrg(ctx, org.ID)
		if err != nil || len(list) != 1 {
			t.Fatalf("SAMLConnectionsByOrg = %d, %v", len(list), err)
		}
		_, err = s.SAMLConnectionByID(ctx, newID())
		wantNotFound(t, "missing connection", err)
	})

	t.Run("UnknownOrganizationRejected", func(t *testing.T) {
		_, err := s.InsertSAMLConnection(ctx, theauth.SAMLConnection{ID: newID(), OrganizationID: newID(), CreatedAt: now})
		if err == nil {
			t.Fatal("connection for an unknown organization was accepted")
		}
	})

	t.Run("Update", func(t *testing.T) {
		conn.IdPSSOURL = "https://idp.example/sso2"
		if err := s.UpdateSAMLConnectionRow(ctx, conn); err != nil {
			t.Fatalf("UpdateSAMLConnectionRow: %v", err)
		}
		got, _ := s.SAMLConnectionByID(ctx, conn.ID)
		if got == nil || got.IdPSSOURL != "https://idp.example/sso2" {
			t.Fatalf("after update: %+v", got)
		}
		ghost := conn
		ghost.ID = newID()
		wantNotFound(t, "update missing", s.UpdateSAMLConnectionRow(ctx, ghost))
	})

	t.Run("Identities", func(t *testing.T) {
		first, err := s.UpsertSAMLIdentity(ctx, theauth.SAMLIdentity{
			ID: newID(), ConnectionID: conn.ID, UserID: user.ID, NameID: "name-1", NameIDFormat: "email", CreatedAt: now,
		})
		if err != nil {
			t.Fatalf("UpsertSAMLIdentity: %v", err)
		}
		again, err := s.UpsertSAMLIdentity(ctx, theauth.SAMLIdentity{
			ID: newID(), ConnectionID: conn.ID, UserID: user.ID, NameID: "name-1", NameIDFormat: "persistent", CreatedAt: now,
		})
		if err != nil || again.ID != first.ID || again.NameIDFormat != "persistent" {
			t.Fatalf("upsert not idempotent on (connection, name id): %+v, %v", again, err)
		}
		at := time.Now().Truncate(time.Microsecond)
		if err := s.TouchSAMLIdentityLastLogin(ctx, first.ID, at); err != nil {
			t.Fatalf("Touch: %v", err)
		}
		got, err := s.SAMLIdentityByConnectionAndNameID(ctx, conn.ID, "name-1")
		if err != nil || got.LastLoginAt == nil || !got.LastLoginAt.Equal(at) {
			t.Fatalf("identity = %+v, %v", got, err)
		}
		_, err = s.SAMLIdentityByConnectionAndNameID(ctx, conn.ID, "NAME-1")
		wantNotFound(t, "name id is case sensitive", err)
	})

	t.Run("DeleteCascades", func(t *testing.T) {
		if err := s.DeleteSAMLConnection(ctx, conn.ID); err != nil {
			t.Fatalf("DeleteSAMLConnection: %v", err)
		}
		_, err := s.SAMLIdentityByConnectionAndNameID(ctx, conn.ID, "name-1")
		wantNotFound(t, "identity after connection delete", err)
		wantNotFound(t, "second delete", s.DeleteSAMLConnection(ctx, conn.ID))
	})

	t.Run("OrganizationDeleteCascades", func(t *testing.T) {
		o := mustOrg(t, s, "saml-cascade")
		c, err := s.InsertSAMLConnection(ctx, theauth.SAMLConnection{ID: newID(), OrganizationID: o.ID, CreatedAt: now})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteOrganization(ctx, o.ID); err != nil {
			t.Fatal(err)
		}
		_, err = s.SAMLConnectionByID(ctx, c.ID)
		wantNotFound(t, "connection after org delete", err)
	})
}

func testSCIM(t *testing.T, s EnterpriseSuiteStorage) {
	ctx := context.Background()
	orgA := mustOrg(t, s, "scim-a")
	orgB := mustOrg(t, s, "scim-b")
	now := time.Now()

	t.Run("Tokens", func(t *testing.T) {
		hash := sha256Hash([]byte("plaintext-token"))
		tok, err := s.InsertSCIMToken(ctx, theauth.SCIMToken{ID: newID(), OrganizationID: orgA.ID, TokenHash: hash, Name: "okta", CreatedAt: now})
		if err != nil {
			t.Fatalf("InsertSCIMToken: %v", err)
		}
		if _, err := s.InsertSCIMToken(ctx, theauth.SCIMToken{ID: newID(), OrganizationID: orgB.ID, TokenHash: hash, CreatedAt: now}); err == nil {
			t.Fatal("duplicate token hash was accepted")
		}
		if _, err := s.InsertSCIMToken(ctx, theauth.SCIMToken{ID: newID(), OrganizationID: newID(), TokenHash: sha256Hash([]byte("x")), CreatedAt: now}); err == nil {
			t.Fatal("token for an unknown organization was accepted")
		}
		got, err := s.SCIMTokenByHash(ctx, hash)
		if err != nil || got.ID != tok.ID || got.OrganizationID != orgA.ID || got.RevokedAt != nil {
			t.Fatalf("SCIMTokenByHash = %+v, %v", got, err)
		}
		_, err = s.SCIMTokenByHash(ctx, sha256Hash([]byte("other")))
		wantNotFound(t, "unknown hash", err)
		used := time.Now().Truncate(time.Microsecond)
		if err := s.TouchSCIMTokenLastUsed(ctx, tok.ID, used); err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeSCIMTokenByID(ctx, tok.ID, used); err != nil {
			t.Fatal(err)
		}
		got, _ = s.SCIMTokenByHash(ctx, hash)
		if got == nil || got.RevokedAt == nil || got.LastUsedAt == nil || !got.LastUsedAt.Equal(used) {
			t.Fatalf("after revoke: %+v", got)
		}
		list, err := s.SCIMTokensByOrg(ctx, orgA.ID)
		if err != nil || len(list) != 1 {
			t.Fatalf("SCIMTokensByOrg = %d, %v", len(list), err)
		}
		wantNotFound(t, "revoke missing", s.RevokeSCIMTokenByID(ctx, newID(), used))
	})

	t.Run("UserListingIsOrgScoped", func(t *testing.T) {
		var users []theauth.User
		for i := 0; i < 3; i++ {
			u := mustUser(t, s, fmt.Sprintf("scim-user-%d@storagetest.example", i))
			u.ExternalID = fmt.Sprintf("ext-%d", i)
			u.GivenName, u.FamilyName, u.DisplayName = "Given", "Family", "Display"
			if err := s.UpdateUserSCIM(ctx, u); err != nil {
				t.Fatalf("UpdateUserSCIM: %v", err)
			}
			mustMember(t, s, orgA.ID, u.ID, "member")
			users = append(users, u)
		}
		outsider := mustUser(t, s, "scim-outsider@storagetest.example")
		outsider.ExternalID = "ext-0"
		if err := s.UpdateUserSCIM(ctx, outsider); err != nil {
			t.Fatal(err)
		}
		mustMember(t, s, orgB.ID, outsider.ID, "member")

		all, total, err := s.ListUsersByOrganization(ctx, orgA.ID, 0, 0, theauth.SCIMUserFilter{})
		if err != nil || total != 3 || len(all) != 3 {
			t.Fatalf("list = %d/%d, %v", len(all), total, err)
		}
		page, total, err := s.ListUsersByOrganization(ctx, orgA.ID, 1, 1, theauth.SCIMUserFilter{})
		if err != nil || total != 3 || len(page) != 1 {
			t.Fatalf("page = %d/%d, %v", len(page), total, err)
		}
		byExt, total, _ := s.ListUsersByOrganization(ctx, orgA.ID, 0, 10, theauth.SCIMUserFilter{ExternalID: "ext-0"})
		if total != 1 || len(byExt) != 1 || byExt[0].ID != users[0].ID {
			t.Fatalf("external filter leaked across organizations: %+v", byExt)
		}
		byMail, total, _ := s.ListUsersByOrganization(ctx, orgA.ID, 0, 10, theauth.SCIMUserFilter{UserName: "SCIM-USER-1@storagetest.example"})
		if total != 1 || len(byMail) != 1 || byMail[0].ID != users[1].ID {
			t.Fatalf("userName filter: %+v", byMail)
		}
		got, err := s.UserByExternalIDInOrg(ctx, orgA.ID, "ext-0")
		if err != nil || got.ID != users[0].ID || got.GivenName != "Given" {
			t.Fatalf("UserByExternalIDInOrg = %+v, %v", got, err)
		}
		_, err = s.UserByExternalIDInOrg(ctx, orgA.ID, "")
		wantNotFound(t, "empty external id", err)
		_, err = s.UserByExternalIDInOrg(ctx, orgB.ID, "ext-1")
		wantNotFound(t, "external id of another org", err)
		wantNotFound(t, "update missing user", s.UpdateUserSCIM(ctx, theauth.User{ID: newID(), Email: "nobody@storagetest.example"}))
	})

	t.Run("Groups", func(t *testing.T) {
		g, err := s.InsertGroup(ctx, theauth.Group{ID: newID(), OrganizationID: orgA.ID, DisplayName: "Engineering", ExternalID: "g-1", CreatedAt: now})
		if err != nil {
			t.Fatalf("InsertGroup: %v", err)
		}
		if _, err := s.InsertGroup(ctx, theauth.Group{ID: newID(), OrganizationID: orgA.ID, DisplayName: "Engineering", CreatedAt: now}); err == nil {
			t.Fatal("duplicate display name in one organization was accepted")
		}
		if _, err := s.InsertGroup(ctx, theauth.Group{ID: newID(), OrganizationID: orgB.ID, DisplayName: "Engineering", ExternalID: "g-1", CreatedAt: now}); err != nil {
			t.Fatalf("same names in another organization must be allowed: %v", err)
		}
		// Two groups without an external id must not collide.
		for _, n := range []string{"NoExtA", "NoExtB"} {
			if _, err := s.InsertGroup(ctx, theauth.Group{ID: newID(), OrganizationID: orgA.ID, DisplayName: n, CreatedAt: now}); err != nil {
				t.Fatalf("group without external id %s: %v", n, err)
			}
		}
		byExt, err := s.GroupByExternalIDInOrg(ctx, orgA.ID, "g-1")
		if err != nil || byExt.ID != g.ID {
			t.Fatalf("GroupByExternalIDInOrg = %+v, %v", byExt, err)
		}
		_, err = s.GroupByExternalIDInOrg(ctx, orgA.ID, "")
		wantNotFound(t, "empty group external id", err)
		list, total, err := s.ListGroupsByOrganization(ctx, orgA.ID, 0, 10, theauth.SCIMGroupFilter{})
		if err != nil || total != 3 || len(list) != 3 {
			t.Fatalf("ListGroupsByOrganization = %d/%d, %v", len(list), total, err)
		}
		filtered, total, _ := s.ListGroupsByOrganization(ctx, orgA.ID, 0, 10, theauth.SCIMGroupFilter{DisplayName: "Engineering"})
		if total != 1 || len(filtered) != 1 {
			t.Fatalf("group filter = %d/%d", len(filtered), total)
		}

		m1 := mustUser(t, s, "grp-1@storagetest.example")
		m2 := mustUser(t, s, "grp-2@storagetest.example")
		if err := s.SetGroupMembers(ctx, g.ID, []theauth.ULID{m1.ID, m2.ID}); err != nil {
			t.Fatalf("SetGroupMembers: %v", err)
		}
		if err := s.AddGroupMembers(ctx, g.ID, []theauth.ULID{m1.ID}); err != nil {
			t.Fatalf("AddGroupMembers (existing): %v", err)
		}
		if members, _ := s.GroupMembers(ctx, g.ID); len(members) != 2 {
			t.Fatalf("members = %d, want 2", len(members))
		}
		if err := s.RemoveGroupMembers(ctx, g.ID, []theauth.ULID{m1.ID}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetGroupMembers(ctx, g.ID, []theauth.ULID{newID()}); err == nil {
			t.Fatal("unknown member user was accepted")
		}
		if members, _ := s.GroupMembers(ctx, g.ID); len(members) != 1 || members[0] != m2.ID {
			t.Fatalf("failed SetGroupMembers must leave the set untouched, got %v", members)
		}

		g.DisplayName = "Platform"
		g.ExternalID = ""
		if err := s.UpdateGroup(ctx, g); err != nil {
			t.Fatalf("UpdateGroup: %v", err)
		}
		got, _ := s.GroupByID(ctx, g.ID)
		if got == nil || got.DisplayName != "Platform" || got.ExternalID != "" {
			t.Fatalf("after update: %+v", got)
		}
		if err := s.DeleteGroup(ctx, g.ID); err != nil {
			t.Fatal(err)
		}
		_, err = s.GroupByID(ctx, g.ID)
		wantNotFound(t, "group after delete", err)
		wantNotFound(t, "delete missing group", s.DeleteGroup(ctx, g.ID))
	})
}

func testOrgScopedRBAC(t *testing.T, s EnterpriseSuiteStorage) {
	ctx := context.Background()
	orgA := mustOrg(t, s, "rbac-a")
	orgB := mustOrg(t, s, "rbac-b")
	user := mustUser(t, s, "rbac-org-user@storagetest.example")
	perm, err := s.InsertPermission(ctx, theauth.Permission{ID: newID(), Name: "org-suite:deploy", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	mkRole := func(org *theauth.ULID, name string) (theauth.Role, error) {
		return s.InsertRole(ctx, theauth.Role{ID: newID(), OrganizationID: org, Name: name, CreatedAt: time.Now()})
	}

	t.Run("NameUniqueness", func(t *testing.T) {
		if _, err := mkRole(&orgA.ID, "deployer"); err != nil {
			t.Fatal(err)
		}
		if _, err := mkRole(&orgA.ID, "deployer"); err == nil {
			t.Fatal("duplicate role name in one organization was accepted")
		}
		if _, err := mkRole(&orgB.ID, "deployer"); err != nil {
			t.Fatalf("same role name in another organization: %v", err)
		}
		if _, err := mkRole(nil, "deployer"); err != nil {
			t.Fatalf("system role sharing an organization role name: %v", err)
		}
		if _, err := mkRole(nil, "deployer"); err == nil {
			t.Fatal("duplicate system role name was accepted")
		}
	})

	t.Run("ScopedGrantsAndCounts", func(t *testing.T) {
		role, err := s.RoleByOrgAndName(ctx, &orgA.ID, "deployer")
		if err != nil {
			t.Fatalf("RoleByOrgAndName: %v", err)
		}
		if err := s.SetRolePermissions(ctx, role.ID, []theauth.ULID{perm.ID}); err != nil {
			t.Fatal(err)
		}
		if err := s.GrantUserRole(ctx, theauth.UserRole{UserID: user.ID, RoleID: role.ID, GrantedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if names, _ := s.PermissionsForUser(ctx, user.ID, &orgA.ID); len(names) != 1 || names[0] != "org-suite:deploy" {
			t.Fatalf("org A permissions = %v", names)
		}
		if names, _ := s.PermissionsForUser(ctx, user.ID, &orgB.ID); len(names) != 0 {
			t.Fatalf("permissions leaked into org B: %v", names)
		}
		if n, err := s.CountUsersWithPermissionInOrg(ctx, orgA.ID, "org-suite:deploy"); err != nil || n != 1 {
			t.Fatalf("count A = %d, %v", n, err)
		}
		if n, _ := s.CountUsersWithPermissionInOrg(ctx, orgB.ID, "org-suite:deploy"); n != 0 {
			t.Fatalf("count B = %d, want 0", n)
		}
		roles, err := s.RolesByOrganization(ctx, &orgA.ID)
		if err != nil || len(roles) != 1 || len(roles[0].Permissions) != 1 {
			t.Fatalf("RolesByOrganization = %+v, %v", roles, err)
		}
	})

	t.Run("PermissionInUseCannotVanish", func(t *testing.T) {
		role, _ := s.RoleByOrgAndName(ctx, &orgA.ID, "deployer")
		if err := s.DeleteRole(ctx, role.ID); err != nil {
			t.Fatalf("DeleteRole: %v", err)
		}
		if names, _ := s.PermissionsForUser(ctx, user.ID, &orgA.ID); len(names) != 0 {
			t.Fatalf("grant survived role delete: %v", names)
		}
		if _, err := s.PermissionByName(ctx, "org-suite:deploy"); err != nil {
			t.Fatalf("permission must outlive its roles: %v", err)
		}
	})
}
