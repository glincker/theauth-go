package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

func testTOTPSecrets(t *testing.T, store theauth.Storage) {
	t.Helper()
	ctx := context.Background()

	uid := newID()
	if _, err := store.CreateUser(ctx, theauth.User{
		ID:        uid,
		Email:     "totp-owner@storagetest.example",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	t.Run("UpsertPendingAndFetch", func(t *testing.T) {
		sec := theauth.TOTPSecret{
			UserID:    uid,
			SecretEnc: []byte("encrypted-secret-bytes"),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := store.UpsertPendingTOTPSecret(ctx, sec); err != nil {
			t.Fatalf("UpsertPendingTOTPSecret: %v", err)
		}

		got, err := store.TOTPSecretByUserID(ctx, uid)
		if err != nil {
			t.Fatalf("TOTPSecretByUserID: %v", err)
		}
		if got.ConfirmedAt != nil {
			t.Fatal("pending secret must have nil ConfirmedAt")
		}
	})

	t.Run("ConfirmSecret", func(t *testing.T) {
		if err := store.ConfirmTOTPSecret(ctx, uid, time.Now()); err != nil {
			t.Fatalf("ConfirmTOTPSecret: %v", err)
		}

		got, err := store.TOTPSecretByUserID(ctx, uid)
		if err != nil {
			t.Fatalf("TOTPSecretByUserID after confirm: %v", err)
		}
		if got.ConfirmedAt == nil {
			t.Fatal("ConfirmedAt should be set after ConfirmTOTPSecret")
		}
	})

	t.Run("UpsertPendingPreservesConfirmed", func(t *testing.T) {
		// Upserting a new pending secret while a confirmed one exists must be a no-op.
		sec2 := theauth.TOTPSecret{
			UserID:    uid,
			SecretEnc: []byte("new-pending-bytes"),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := store.UpsertPendingTOTPSecret(ctx, sec2); err != nil {
			t.Fatalf("UpsertPendingTOTPSecret (re-enroll): %v", err)
		}

		got, err := store.TOTPSecretByUserID(ctx, uid)
		if err != nil {
			t.Fatalf("TOTPSecretByUserID: %v", err)
		}
		if got.ConfirmedAt == nil {
			t.Fatal("confirmed secret should not be overwritten by a pending upsert")
		}
	})

	t.Run("DeleteAndMissing", func(t *testing.T) {
		if err := store.DeleteTOTPSecret(ctx, uid); err != nil {
			t.Fatalf("DeleteTOTPSecret: %v", err)
		}

		if _, err := store.TOTPSecretByUserID(ctx, uid); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("after delete: want ErrNotFound, got %v", err)
		}
	})

	t.Run("ConfirmMissingSecret", func(t *testing.T) {
		uid2 := newID()
		if _, err := store.CreateUser(ctx, theauth.User{
			ID:        uid2,
			Email:     "totp-noexist@storagetest.example",
			CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := store.ConfirmTOTPSecret(ctx, uid2, time.Now()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("confirm missing secret: want ErrNotFound, got %v", err)
		}
	})
}
