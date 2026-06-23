package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

func testRefreshTokens(t *testing.T, store theauth.OAuthServerStorage) {
	t.Helper()
	ctx := context.Background()

	userID := newID()

	makeToken := func(hash []byte, familyID theauth.ULID) theauth.RefreshToken {
		return theauth.RefreshToken{
			ID:        newID(),
			Hash:      hash,
			FamilyID:  familyID,
			ClientID:  "st-rt-client",
			UserID:    &userID,
			Scope:     []string{"openid"},
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
	}

	t.Run("InsertAndFetchByHash", func(t *testing.T) {
		hash := sha256Hash([]byte("rt-fetch"))
		familyID := newID()
		tok := makeToken(hash, familyID)

		if err := store.InsertRefreshToken(ctx, tok); err != nil {
			t.Fatalf("InsertRefreshToken: %v", err)
		}

		got, err := store.RefreshTokenByHash(ctx, hash)
		if err != nil {
			t.Fatalf("RefreshTokenByHash: %v", err)
		}
		if got.ID != tok.ID {
			t.Fatalf("ID mismatch")
		}
		if got.RevokedAt != nil {
			t.Fatal("fresh token must not be revoked")
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		hash := sha256Hash([]byte("rt-revoke"))
		tok := makeToken(hash, newID())

		if err := store.InsertRefreshToken(ctx, tok); err != nil {
			t.Fatalf("InsertRefreshToken: %v", err)
		}
		if err := store.RevokeRefreshToken(ctx, hash, "test revocation"); err != nil {
			t.Fatalf("RevokeRefreshToken: %v", err)
		}

		got, err := store.RefreshTokenByHash(ctx, hash)
		if err != nil {
			t.Fatalf("RefreshTokenByHash after revoke: %v", err)
		}
		if got.RevokedAt == nil {
			t.Fatal("RevokedAt should be set after RevokeRefreshToken")
		}
	})

	t.Run("RevokeMissing", func(t *testing.T) {
		err := store.RevokeRefreshToken(ctx, sha256Hash([]byte("no-such-rt")), "reason")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("RevokeFamily", func(t *testing.T) {
		familyID := newID()
		var hashes [][]byte
		for i := 0; i < 3; i++ {
			h := sha256Hash([]byte{byte(i), 0xfa, 0xce})
			hashes = append(hashes, h)
			if err := store.InsertRefreshToken(ctx, makeToken(h, familyID)); err != nil {
				t.Fatalf("InsertRefreshToken[%d]: %v", i, err)
			}
		}

		if err := store.RevokeRefreshTokenFamily(ctx, familyID, "family replay"); err != nil {
			t.Fatalf("RevokeRefreshTokenFamily: %v", err)
		}

		for i, h := range hashes {
			got, err := store.RefreshTokenByHash(ctx, h)
			if err != nil {
				t.Fatalf("RefreshTokenByHash[%d]: %v", i, err)
			}
			if got.RevokedAt == nil {
				t.Fatalf("token[%d] RevokedAt should be set after family revoke", i)
			}
		}
	})

	t.Run("FetchMissing", func(t *testing.T) {
		if _, err := store.RefreshTokenByHash(ctx, sha256Hash([]byte("no-rt"))); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
}
