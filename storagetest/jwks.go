package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

func testJWKSKeys(t *testing.T, store theauth.OAuthServerStorage) {
	t.Helper()
	ctx := context.Background()

	kid1 := "st-jwks-kid-" + newID().String()
	kid2 := "st-jwks-kid2-" + newID().String()

	t.Run("InsertAndFetch", func(t *testing.T) {
		k := theauth.JWKSKey{
			KID:        kid1,
			Alg:        "EdDSA",
			Use:        "sig",
			PublicJWK:  []byte(`{"kty":"OKP","crv":"Ed25519","x":"fake"}`),
			PrivateEnc: []byte("encrypted-private-bytes"),
			State:      theauth.JWKSStateNext,
			CreatedAt:  time.Now(),
		}
		if err := store.InsertJWKSKey(ctx, k); err != nil {
			t.Fatalf("InsertJWKSKey: %v", err)
		}

		got, err := store.JWKSKeyByKID(ctx, kid1)
		if err != nil {
			t.Fatalf("JWKSKeyByKID: %v", err)
		}
		if got.State != theauth.JWKSStateNext {
			t.Fatalf("State: want %q got %q", theauth.JWKSStateNext, got.State)
		}
	})

	t.Run("InsertDuplicateKIDFails", func(t *testing.T) {
		k := theauth.JWKSKey{
			KID:       kid1,
			Alg:       "EdDSA",
			Use:       "sig",
			State:     theauth.JWKSStateNext,
			CreatedAt: time.Now(),
		}
		err := store.InsertJWKSKey(ctx, k)
		if err == nil {
			t.Fatal("InsertJWKSKey with duplicate KID: want error, got nil")
		}
	})

	t.Run("StateTransitionNextToCurrent", func(t *testing.T) {
		now := time.Now()
		if err := store.UpdateJWKSKeyState(ctx, kid1, theauth.JWKSStateCurrent, now); err != nil {
			t.Fatalf("UpdateJWKSKeyState (current): %v", err)
		}

		got, err := store.JWKSKeyByKID(ctx, kid1)
		if err != nil {
			t.Fatalf("JWKSKeyByKID after promote: %v", err)
		}
		if got.State != theauth.JWKSStateCurrent {
			t.Fatalf("State: want current, got %q", got.State)
		}
		if got.PromotedAt == nil {
			t.Fatal("PromotedAt should be set after transition to current")
		}
	})

	t.Run("StateTransitionCurrentToRetired", func(t *testing.T) {
		now := time.Now()
		if err := store.UpdateJWKSKeyState(ctx, kid1, theauth.JWKSStateRetired, now); err != nil {
			t.Fatalf("UpdateJWKSKeyState (retired): %v", err)
		}

		got, err := store.JWKSKeyByKID(ctx, kid1)
		if err != nil {
			t.Fatalf("JWKSKeyByKID after retire: %v", err)
		}
		if got.State != theauth.JWKSStateRetired {
			t.Fatalf("State: want retired, got %q", got.State)
		}
		if got.RetiredAt == nil {
			t.Fatal("RetiredAt should be set after transition to retired")
		}
	})

	t.Run("JWKSKeysAll", func(t *testing.T) {
		// Insert a second key so JWKSKeysAll returns at least 2.
		k2 := theauth.JWKSKey{
			KID:       kid2,
			Alg:       "EdDSA",
			Use:       "sig",
			State:     theauth.JWKSStateCurrent,
			CreatedAt: time.Now(),
		}
		if err := store.InsertJWKSKey(ctx, k2); err != nil {
			t.Fatalf("InsertJWKSKey kid2: %v", err)
		}

		keys, err := store.JWKSKeysAll(ctx)
		if err != nil {
			t.Fatalf("JWKSKeysAll: %v", err)
		}
		found := 0
		for _, k := range keys {
			if k.KID == kid1 || k.KID == kid2 {
				found++
			}
		}
		if found < 2 {
			t.Fatalf("JWKSKeysAll: expected both keys, found %d", found)
		}
	})

	t.Run("UpdateMissingKIDFails", func(t *testing.T) {
		err := store.UpdateJWKSKeyState(ctx, "no-such-kid", theauth.JWKSStateCurrent, time.Now())
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("FetchMissingKIDFails", func(t *testing.T) {
		if _, err := store.JWKSKeyByKID(ctx, "absent-kid"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
}
