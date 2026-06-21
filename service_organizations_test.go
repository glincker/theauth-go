package theauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
)

func newOrgTestAuth(t *testing.T) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://example.test",
		Organizations: &theauth.OrganizationsConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, store
}

func newUser(t *testing.T, store *memory.Store, email string) theauth.User {
	t.Helper()
	u := theauth.User{ID: ulid.New(), Email: email, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if _, err := store.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestOrganizationCreateAddsOwner(t *testing.T) {
	a, store := newOrgTestAuth(t)
	owner := newUser(t, store, "owner@x.test")
	org, err := a.CreateOrganization(context.Background(), "Acme", "acme", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if org.Slug != "acme" {
		t.Fatalf("want slug acme, got %q", org.Slug)
	}
	members, err := a.ListOrganizationMembers(context.Background(), org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].UserID != owner.ID || members[0].Role != theauth.OrgRoleOwner {
		t.Fatalf("expected single owner member, got %+v", members)
	}
}

func TestOrganizationSlugUniqueness(t *testing.T) {
	a, store := newOrgTestAuth(t)
	owner := newUser(t, store, "owner@x.test")
	if _, err := a.CreateOrganization(context.Background(), "Acme", "acme", owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateOrganization(context.Background(), "Acme 2", "acme", owner.ID); !errors.Is(err, theauth.ErrSlugTaken) {
		t.Fatalf("want ErrSlugTaken, got %v", err)
	}
}

func TestOrganizationSlugValidation(t *testing.T) {
	a, store := newOrgTestAuth(t)
	owner := newUser(t, store, "owner@x.test")
	cases := []string{"", "bad slug", "_underscore", "-leading", "trailing-", "with.dot"}
	for _, c := range cases {
		if _, err := a.CreateOrganization(context.Background(), "n", c, owner.ID); err == nil {
			t.Fatalf("slug %q should have been rejected", c)
		}
	}
}

func TestOrganizationMemberRoleAndRemoval(t *testing.T) {
	a, store := newOrgTestAuth(t)
	owner := newUser(t, store, "owner@x.test")
	member := newUser(t, store, "member@x.test")
	org, err := a.CreateOrganization(context.Background(), "Acme", "acme", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddOrganizationMember(context.Background(), org.ID, member.ID, theauth.OrgRoleMember); err != nil {
		t.Fatal(err)
	}
	if err := a.RemoveOrganizationMember(context.Background(), org.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	// Removing the last owner is forbidden.
	if err := a.RemoveOrganizationMember(context.Background(), org.ID, owner.ID); !errors.Is(err, theauth.ErrLastOwner) {
		t.Fatalf("want ErrLastOwner, got %v", err)
	}
}

func TestSetActiveOrganization(t *testing.T) {
	a, store := newOrgTestAuth(t)
	owner := newUser(t, store, "owner@x.test")
	org, _ := a.CreateOrganization(context.Background(), "Acme", "acme", owner.ID)
	// Mint a session for the owner directly via storage so we don't depend
	// on the magic-link flow here.
	sess := theauth.Session{ID: ulid.New(), UserID: owner.ID, TokenHash: []byte("t"), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if _, err := store.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	orgID := org.ID
	if err := a.SetActiveOrganization(context.Background(), sess.ID, &orgID); err != nil {
		t.Fatal(err)
	}
	got, err := store.SessionByTokenHash(context.Background(), []byte("t"))
	if err != nil {
		t.Fatal(err)
	}
	if got.ActiveOrganizationID == nil || *got.ActiveOrganizationID != orgID {
		t.Fatalf("active org not set: %+v", got)
	}
	if err := a.SetActiveOrganization(context.Background(), sess.ID, nil); err != nil {
		t.Fatal(err)
	}
	got, _ = store.SessionByTokenHash(context.Background(), []byte("t"))
	if got.ActiveOrganizationID != nil {
		t.Fatalf("expected cleared active org, got %v", got.ActiveOrganizationID)
	}
}
