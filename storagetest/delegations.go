package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

func testDelegations(t *testing.T, store theauth.OAuthServerStorage) {
	t.Helper()
	ctx := context.Background()

	userID := newID()
	agentID := newID()
	const resource = "https://api.storagetest.example"

	makeGrant := func(uid, aid theauth.ULID, res string) theauth.DelegationGrant {
		return theauth.DelegationGrant{
			ID:                 newID(),
			UserID:             uid,
			AgentID:            aid,
			Scope:              []string{"openid", "read"},
			Resource:           res,
			MaxDurationSeconds: 3600,
			CreatedAt:          time.Now(),
		}
	}

	var grantID theauth.ULID

	t.Run("CreateAndFetchByID", func(t *testing.T) {
		g := makeGrant(userID, agentID, resource)
		got, err := store.InsertDelegationGrant(ctx, g)
		if err != nil {
			t.Fatalf("InsertDelegationGrant: %v", err)
		}
		grantID = got.ID

		fetched, err := store.DelegationGrantByID(ctx, grantID)
		if err != nil {
			t.Fatalf("DelegationGrantByID: %v", err)
		}
		if fetched.UserID != userID {
			t.Fatalf("UserID mismatch")
		}
	})

	t.Run("FetchByUserAgentResource", func(t *testing.T) {
		got, err := store.DelegationGrantByUserAgentResource(ctx, userID, agentID, resource)
		if err != nil {
			t.Fatalf("DelegationGrantByUserAgentResource: %v", err)
		}
		if got.ID != grantID {
			t.Fatalf("ID mismatch: want %s, got %s", grantID, got.ID)
		}
	})

	t.Run("ListByUserID", func(t *testing.T) {
		grants, err := store.DelegationGrantsByUserID(ctx, userID)
		if err != nil {
			t.Fatalf("DelegationGrantsByUserID: %v", err)
		}
		if len(grants) < 1 {
			t.Fatal("expected at least 1 grant")
		}
	})

	t.Run("ListByAgentID", func(t *testing.T) {
		grants, err := store.DelegationGrantsByAgentID(ctx, agentID)
		if err != nil {
			t.Fatalf("DelegationGrantsByAgentID: %v", err)
		}
		if len(grants) < 1 {
			t.Fatal("expected at least 1 grant")
		}
	})

	t.Run("RevokeAndFetch", func(t *testing.T) {
		if err := store.RevokeDelegationGrant(ctx, grantID, time.Now(), "storagetest revoke"); err != nil {
			t.Fatalf("RevokeDelegationGrant: %v", err)
		}

		got, err := store.DelegationGrantByID(ctx, grantID)
		if err != nil {
			t.Fatalf("DelegationGrantByID after revoke: %v", err)
		}
		if got.RevokedAt == nil {
			t.Fatal("RevokedAt should be set after RevokeDelegationGrant")
		}
		if got.RevocationNote != "storagetest revoke" {
			t.Fatalf("RevocationNote: want %q, got %q", "storagetest revoke", got.RevocationNote)
		}
	})

	t.Run("FetchMissing", func(t *testing.T) {
		if _, err := store.DelegationGrantByID(ctx, newID()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("FetchByTupleMissing", func(t *testing.T) {
		_, err := store.DelegationGrantByUserAgentResource(ctx, newID(), newID(), "https://no.example")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("RevokeReplaceWithFreshGrant", func(t *testing.T) {
		// After revocation, inserting a new grant for the same tuple must succeed.
		g2 := makeGrant(userID, agentID, resource)
		got, err := store.InsertDelegationGrant(ctx, g2)
		if err != nil {
			t.Fatalf("InsertDelegationGrant after revoke: %v", err)
		}
		if got.RevokedAt != nil {
			t.Fatal("fresh grant must not be revoked")
		}
	})
}
