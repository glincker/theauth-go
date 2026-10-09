package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
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

	t.Run("RevokeTwiceIsConditional", func(t *testing.T) {
		hash := sha256Hash([]byte("rt-revoke-twice"))
		if err := store.InsertRefreshToken(ctx, makeToken(hash, newID())); err != nil {
			t.Fatal(err)
		}
		if err := store.RevokeRefreshToken(ctx, hash, "first"); err != nil {
			t.Fatalf("first revoke: %v", err)
		}
		if err := store.RevokeRefreshToken(ctx, hash, "second"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("second revoke must be ErrNotFound, got %v", err)
		}
	})

	t.Run("BindingFieldsRoundTrip", func(t *testing.T) {
		hash := sha256Hash([]byte("rt-binding"))
		tok := makeToken(hash, newID())
		tok.DPoPJKT = "jkt-thumbprint"
		tok.AuthCodeHash = "codehash-roundtrip"
		if err := store.InsertRefreshToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		got, err := store.RefreshTokenByHash(ctx, hash)
		if err != nil {
			t.Fatal(err)
		}
		if got.DPoPJKT != tok.DPoPJKT || got.AuthCodeHash != tok.AuthCodeHash {
			t.Fatalf("binding fields lost: %+v", got)
		}
	})

	t.Run("AuthorizationDetailsRoundTrip", func(t *testing.T) {
		hash := sha256Hash([]byte("rt-rar"))
		tok := makeToken(hash, newID())
		tok.AuthorizationDetails = []byte(`[{"type":"payment","actions":["initiate"]}]`)
		if err := store.InsertRefreshToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		got, err := store.RefreshTokenByHash(ctx, hash)
		if err != nil {
			t.Fatal(err)
		}
		if string(normalizeJSON(got.AuthorizationDetails)) != string(normalizeJSON(tok.AuthorizationDetails)) {
			t.Fatalf("authorization_details lost: %s", got.AuthorizationDetails)
		}
	})

	t.Run("RevokeByAuthCode", func(t *testing.T) {
		rs, ok := store.(interface {
			RevokeRefreshTokensByAuthCode(ctx context.Context, codeHash, reason string) ([]string, error)
		})
		if !ok {
			t.Skip("storage does not implement RevokeRefreshTokensByAuthCode")
		}
		fam := newID()
		hash := sha256Hash([]byte("rt-by-code"))
		tok := makeToken(hash, fam)
		tok.AuthCodeHash = "codehash-revoke"
		tok.ParentJTI = "jti-from-code"
		if err := store.InsertRefreshToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		jtis, err := rs.RevokeRefreshTokensByAuthCode(ctx, "codehash-revoke", "replay")
		if err != nil {
			t.Fatal(err)
		}
		if len(jtis) != 1 || jtis[0] != "jti-from-code" {
			t.Fatalf("jtis=%v", jtis)
		}
		got, _ := store.RefreshTokenByHash(ctx, hash)
		if got == nil || got.RevokedAt == nil {
			t.Fatal("token should be revoked")
		}
		if again, _ := rs.RevokeRefreshTokensByAuthCode(ctx, "codehash-revoke", "replay"); len(again) != 0 {
			t.Fatalf("second call must be a no-op, got %v", again)
		}
		if none, err := rs.RevokeRefreshTokensByAuthCode(ctx, "never-issued", "replay"); err != nil || len(none) != 0 {
			t.Fatalf("unknown code: %v %v", none, err)
		}
	})

	t.Run("AccessTokenDenylist", func(t *testing.T) {
		d, ok := store.(interface {
			DenyAccessToken(ctx context.Context, jti string, expiresAt time.Time) error
			IsAccessTokenDenied(ctx context.Context, jti string) (bool, error)
		})
		if !ok {
			t.Skip("storage does not implement the access-token denylist")
		}
		if err := d.DenyAccessToken(ctx, "jti-live", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := d.DenyAccessToken(ctx, "jti-expired", time.Now().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		for jti, want := range map[string]bool{"jti-live": true, "jti-expired": false, "jti-unknown": false} {
			got, err := d.IsAccessTokenDenied(ctx, jti)
			if err != nil || got != want {
				t.Fatalf("IsAccessTokenDenied(%s)=%v,%v want %v", jti, got, err, want)
			}
		}
	})
}
