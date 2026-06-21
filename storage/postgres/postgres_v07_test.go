package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage"
)

// seedOrgAndUser creates an organization, a user, and a member row for
// reuse across the v0.7 postgres tests.
func seedOrgAndUser(t *testing.T, s *Store, email string) (theauth.Organization, theauth.User) {
	t.Helper()
	ctx := context.Background()
	u, err := s.CreateUser(ctx, theauth.User{
		ID:        ulid.New(),
		Email:     email,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	org, err := s.InsertOrganization(ctx, theauth.Organization{
		ID:        ulid.New(),
		Name:      "Acme " + email,
		Slug:      "acme-" + ulid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertOrganizationMember(ctx, theauth.OrganizationMember{
		OrganizationID: org.ID,
		UserID:         u.ID,
		Role:           theauth.OrgRoleOwner,
		JoinedAt:       time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return org, u
}

func TestPostgresOrganizationCRUD(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()
	org, _ := seedOrgAndUser(t, s, "owner@pg.test")

	if got, err := s.OrganizationByID(ctx, org.ID); err != nil || got.Slug != org.Slug {
		t.Fatalf("by id: %v / %+v", err, got)
	}
	if got, err := s.OrganizationBySlug(ctx, org.Slug); err != nil || got.ID != org.ID {
		t.Fatalf("by slug: %v / %+v", err, got)
	}

	// Slug uniqueness
	_, err := s.InsertOrganization(ctx, theauth.Organization{
		ID:   ulid.New(),
		Name: "dup",
		Slug: org.Slug,
	})
	if !errors.Is(err, theauth.ErrSlugTaken) {
		t.Fatalf("want ErrSlugTaken, got %v", err)
	}

	// Delete cascades members
	if err := s.DeleteOrganization(ctx, org.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OrganizationByID(ctx, org.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
}

func TestPostgresSessionActiveOrganizationSetNull(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()
	org, u := seedOrgAndUser(t, s, "sess@pg.test")
	tokenHash := sha256.Sum256([]byte("tok"))
	sess, err := s.CreateSession(ctx, theauth.Session{
		ID:        ulid.New(),
		UserID:    u.ID,
		TokenHash: tokenHash[:],
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	orgID := org.ID
	if err := s.SetSessionActiveOrganization(ctx, sess.ID, &orgID); err != nil {
		t.Fatal(err)
	}
	got, _ := s.SessionByTokenHash(ctx, tokenHash[:])
	if got.ActiveOrganizationID == nil || *got.ActiveOrganizationID != orgID {
		t.Fatalf("active org not set on session row: %+v", got)
	}
	// Delete org -> active_organization_id should be SET NULL on session row
	if err := s.DeleteOrganization(ctx, org.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = s.SessionByTokenHash(ctx, tokenHash[:])
	if got.ActiveOrganizationID != nil {
		t.Fatalf("expected NULL after org delete, got %v", got.ActiveOrganizationID)
	}
}

func TestPostgresSAMLConnectionAndIdentity(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()
	org, u := seedOrgAndUser(t, s, "saml@pg.test")
	conn, err := s.InsertSAMLConnection(ctx, theauth.SAMLConnection{
		ID:             ulid.New(),
		OrganizationID: org.ID,
		IdPEntityID:    "https://idp.test/metadata",
		IdPSSOURL:      "https://idp.test/sso",
		IdPX509Cert:    "PEM-CERT",
		SPEntityID:     "https://sp.test/saml",
		SPACSURL:       "https://sp.test/acs",
		AttributeMap:   theauth.DefaultSAMLAttributeMap(),
	})
	if err != nil {
		t.Fatal(err)
	}
	conns, _ := s.SAMLConnectionsByOrg(ctx, org.ID)
	if len(conns) != 1 {
		t.Fatalf("expected 1 conn, got %d", len(conns))
	}
	// Identity upsert; (connection_id, name_id) is unique
	ident, err := s.UpsertSAMLIdentity(ctx, theauth.SAMLIdentity{
		ID:           ulid.New(),
		ConnectionID: conn.ID,
		UserID:       u.ID,
		NameID:       "name-id-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	ident2, err := s.UpsertSAMLIdentity(ctx, theauth.SAMLIdentity{
		ID:           ulid.New(),
		ConnectionID: conn.ID,
		UserID:       u.ID,
		NameID:       "name-id-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ident.ID != ident2.ID {
		t.Fatalf("upsert returned a different id: %v vs %v", ident.ID, ident2.ID)
	}
}

func TestPostgresSCIMTokenLifecycle(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()
	org, _ := seedOrgAndUser(t, s, "scim@pg.test")
	hash := sha256.Sum256([]byte("token"))
	rec, err := s.InsertSCIMToken(ctx, theauth.SCIMToken{
		ID:             ulid.New(),
		OrganizationID: org.ID,
		Name:           "Okta",
		TokenHash:      hash[:],
		CreatedAt:      time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	found, err := s.SCIMTokenByHash(ctx, hash[:])
	if err != nil || found.ID != rec.ID {
		t.Fatalf("not found: %v / %+v", err, found)
	}
	if err := s.RevokeSCIMTokenByID(ctx, rec.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	found, _ = s.SCIMTokenByHash(ctx, hash[:])
	if found.RevokedAt == nil {
		t.Fatalf("token not marked revoked: %+v", found)
	}
}

func TestPostgresListUsersByOrganizationPaginates(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()
	org, _ := seedOrgAndUser(t, s, "list@pg.test")
	for i := 0; i < 5; i++ {
		u, err := s.CreateUser(ctx, theauth.User{
			ID:        ulid.New(),
			Email:     "u" + ulid.New().String() + "@x.test",
			CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
			UpdatedAt: time.Now(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertOrganizationMember(ctx, theauth.OrganizationMember{
			OrganizationID: org.ID,
			UserID:         u.ID,
			Role:           theauth.OrgRoleMember,
			JoinedAt:       time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	users, total, err := s.ListUsersByOrganization(ctx, org.ID, 0, 3, theauth.SCIMUserFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 6 || len(users) != 3 {
		t.Fatalf("total=%d users=%d", total, len(users))
	}
}

func TestPostgresGroupCRUDAndMembers(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()
	org, u := seedOrgAndUser(t, s, "grp@pg.test")
	g, err := s.InsertGroup(ctx, theauth.Group{
		ID:             ulid.New(),
		OrganizationID: org.ID,
		DisplayName:    "Engineers",
		ExternalID:     "ext-1",
		CreatedAt:      time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembers(ctx, g.ID, []theauth.ULID{u.ID}); err != nil {
		t.Fatal(err)
	}
	members, _ := s.GroupMembers(ctx, g.ID)
	if len(members) != 1 || members[0] != u.ID {
		t.Fatalf("members: %+v", members)
	}
}
