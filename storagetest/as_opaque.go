package storagetest

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// RunOpaqueTokens runs the contract tests for the opaque access token storage
// extension.
func RunOpaqueTokens(t *testing.T, store theauth.OpaqueTokenStorage) {
	t.Helper()
	t.Run("OpaqueTokens", func(t *testing.T) { testOpaqueTokens(t, store) })
}

func testOpaqueTokens(t *testing.T, store theauth.OpaqueTokenStorage) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	rec := theauth.OpaqueAccessToken{
		Hash:      sha256Hash([]byte("opaque-" + now.String())),
		JTI:       "jti-" + now.String(),
		ClientID:  "client-opaque",
		Claims:    []byte(`{"iss":"https://as.example","sub":"u1","aud":"https://api.example","scope":"read"}`),
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}

	t.Run("MissIsNotFound", func(t *testing.T) {
		_, err := store.OpaqueAccessTokenByHash(ctx, sha256Hash([]byte("never-issued")))
		if !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("want ErrStorageNotFound, got %v", err)
		}
	})

	t.Run("InsertAndLookup", func(t *testing.T) {
		if err := store.InsertOpaqueAccessToken(ctx, rec); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := store.OpaqueAccessTokenByHash(ctx, rec.Hash)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if got.ClientID != rec.ClientID || got.JTI != rec.JTI {
			t.Fatalf("got %+v", got)
		}
		if !bytes.Equal(got.Claims, rec.Claims) && string(normalizeJSON(got.Claims)) != string(normalizeJSON(rec.Claims)) {
			t.Fatalf("claims changed: %s", got.Claims)
		}
		if !got.ExpiresAt.Equal(rec.ExpiresAt) {
			t.Fatalf("expires_at %v, want %v", got.ExpiresAt, rec.ExpiresAt)
		}
		if got.RevokedAt != nil {
			t.Fatal("new token must not be revoked")
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		if err := store.RevokeOpaqueAccessToken(ctx, rec.Hash); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		got, err := store.OpaqueAccessTokenByHash(ctx, rec.Hash)
		if err != nil || got.RevokedAt == nil {
			t.Fatalf("want revoked record, got %+v err %v", got, err)
		}
		if err := store.RevokeOpaqueAccessToken(ctx, rec.Hash); err != nil {
			t.Fatalf("second revoke must be a no-op: %v", err)
		}
		if err := store.RevokeOpaqueAccessToken(ctx, sha256Hash([]byte("unknown"))); err != nil {
			t.Fatalf("revoking an unknown token must not fail: %v", err)
		}
	})
}

// normalizeJSON collapses whitespace so backends that re-encode JSON columns
// (Postgres jsonb) still compare equal.
func normalizeJSON(b []byte) []byte {
	return bytes.Join(bytes.Fields(b), nil)
}
