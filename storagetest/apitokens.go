package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// RunAPITokens runs the scoped API token contract tests.
func RunAPITokens(t *testing.T, store theauth.APITokenStorage) {
	t.Helper()
	t.Run("APITokens", func(t *testing.T) { testAPITokens(t, store) })
}

func newTestToken(owner theauth.ULID, kind, secret string, created time.Time) theauth.APIToken {
	exp := created.Add(time.Hour)
	return theauth.APIToken{
		ID: newID(), OwnerID: owner, OwnerKind: kind, Name: "t-" + secret, Abilities: []string{"read", "deploy"},
		TokenHash: sha256Hash([]byte(secret)), Hint: "tk_..." + secret, CreatedAt: created, ExpiresAt: &exp,
	}
}

func testAPITokens(t *testing.T, store theauth.APITokenStorage) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	owner, other := newID(), newID()

	older := newTestToken(owner, theauth.OwnerKindUser, "older-"+owner.String(), now.Add(-time.Minute))
	newer := newTestToken(owner, theauth.OwnerKindUser, "newer-"+owner.String(), now)
	foreign := newTestToken(other, theauth.OwnerKindServiceAccount, "foreign-"+other.String(), now)
	for _, tok := range []theauth.APIToken{older, newer, foreign} {
		if _, err := store.InsertAPIToken(ctx, tok); err != nil {
			t.Fatalf("InsertAPIToken: %v", err)
		}
	}

	t.Run("agent token fields round trip", func(t *testing.T) {
		by := newID()
		agent := newTestToken(by, theauth.OwnerKindUser, "agent-"+by.String(), now)
		agent.Kind, agent.AgentName, agent.DelegatedBy = theauth.APITokenKindAgent, "mcp-client", &by
		if _, err := store.InsertAPIToken(ctx, agent); err != nil {
			t.Fatalf("InsertAPIToken: %v", err)
		}
		got, err := store.APITokenByHash(ctx, agent.TokenHash)
		if err != nil {
			t.Fatalf("APITokenByHash: %v", err)
		}
		if got.Kind != theauth.APITokenKindAgent || got.AgentName != "mcp-client" || got.DelegatedBy == nil || *got.DelegatedBy != by {
			t.Fatalf("agent fields lost: %+v", got)
		}
		if err := store.RevokeAPIToken(ctx, agent.ID, now); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ByHash round trips", func(t *testing.T) {
		got, err := store.APITokenByHash(ctx, newer.TokenHash)
		if err != nil {
			t.Fatalf("APITokenByHash: %v", err)
		}
		if got.ID != newer.ID || got.OwnerID != owner || got.OwnerKind != theauth.OwnerKindUser {
			t.Fatalf("unexpected row: %+v", got)
		}
		if len(got.Abilities) != 2 || got.Abilities[0] != "read" || got.ExpiresAt == nil {
			t.Fatalf("abilities or expiry lost: %+v", got)
		}
	})

	t.Run("lookups miss with ErrStorageNotFound", func(t *testing.T) {
		if _, err := store.APITokenByHash(ctx, sha256Hash([]byte("nope"))); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("ByHash miss: got %v", err)
		}
		if _, err := store.APITokenByID(ctx, newID()); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("ByID miss: got %v", err)
		}
		if err := store.RevokeAPIToken(ctx, newID(), now); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("Revoke miss: got %v", err)
		}
	})

	t.Run("ByOwner is scoped and newest first", func(t *testing.T) {
		got, err := store.APITokensByOwner(ctx, owner)
		if err != nil {
			t.Fatalf("APITokensByOwner: %v", err)
		}
		if len(got) != 2 || got[0].ID != newer.ID || got[1].ID != older.ID {
			t.Fatalf("want [newer older], got %+v", got)
		}
		all, err := store.ListAPITokens(ctx)
		if err != nil {
			t.Fatalf("ListAPITokens: %v", err)
		}
		if len(all) < 3 {
			t.Fatalf("ListAPITokens returned %d rows, want at least 3", len(all))
		}
	})

	t.Run("touch records last used", func(t *testing.T) {
		if err := store.TouchAPITokenLastUsed(ctx, newer.ID, now.Add(time.Second)); err != nil {
			t.Fatalf("Touch: %v", err)
		}
		got, _ := store.APITokenByID(ctx, newer.ID)
		if got.LastUsedAt == nil || got.LastUsedAt.Before(now) {
			t.Fatalf("last_used_at not recorded: %+v", got.LastUsedAt)
		}
	})

	t.Run("revoke is idempotent and keeps the first timestamp", func(t *testing.T) {
		if err := store.RevokeAPIToken(ctx, older.ID, now); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if err := store.RevokeAPIToken(ctx, older.ID, now.Add(time.Hour)); err != nil {
			t.Fatalf("second Revoke: %v", err)
		}
		got, _ := store.APITokenByID(ctx, older.ID)
		if got.RevokedAt == nil || !got.RevokedAt.Equal(now) {
			t.Fatalf("revoked_at = %v, want %v", got.RevokedAt, now)
		}
	})

	t.Run("revoke by owner counts only live tokens", func(t *testing.T) {
		n, err := store.RevokeAPITokensByOwner(ctx, owner, now.Add(time.Minute))
		if err != nil {
			t.Fatalf("RevokeAPITokensByOwner: %v", err)
		}
		if n != 1 {
			t.Fatalf("revoked %d, want 1 (older was already revoked)", n)
		}
		f, _ := store.APITokenByID(ctx, foreign.ID)
		if f.RevokedAt != nil {
			t.Fatal("another owner's token was revoked")
		}
	})
}
