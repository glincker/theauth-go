package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

func testWebAuthnCredentials(t *testing.T, store theauth.Storage) {
	t.Helper()
	ctx := context.Background()

	uid := newID()
	if _, err := store.CreateUser(ctx, theauth.User{
		ID:        uid,
		Email:     "webauthn-owner@storagetest.example",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	credID := []byte("raw-credential-id-bytes-12345678")
	pubKey := []byte("fake-public-key-bytes")

	var credRowID theauth.ULID

	t.Run("Register", func(t *testing.T) {
		c := theauth.WebAuthnCredential{
			ID:           newID(),
			UserID:       uid,
			CredentialID: credID,
			PublicKey:    pubKey,
			SignCount:    0,
			Transports:   []string{"internal"},
			Name:         "Test Key",
			CreatedAt:    time.Now(),
		}
		got, err := store.InsertWebAuthnCredential(ctx, c)
		if err != nil {
			t.Fatalf("InsertWebAuthnCredential: %v", err)
		}
		credRowID = got.ID
	})

	t.Run("ListByUser", func(t *testing.T) {
		creds, err := store.WebAuthnCredentialsByUserID(ctx, uid)
		if err != nil {
			t.Fatalf("WebAuthnCredentialsByUserID: %v", err)
		}
		if len(creds) < 1 {
			t.Fatalf("expected at least 1 credential, got %d", len(creds))
		}
	})

	t.Run("FetchByCredentialID", func(t *testing.T) {
		got, err := store.WebAuthnCredentialByCredentialID(ctx, credID)
		if err != nil {
			t.Fatalf("WebAuthnCredentialByCredentialID: %v", err)
		}
		if got.UserID != uid {
			t.Fatalf("UserID mismatch")
		}
	})

	t.Run("UpdateSignCount", func(t *testing.T) {
		if err := store.UpdateWebAuthnSignCount(ctx, credID, 1, time.Now()); err != nil {
			t.Fatalf("UpdateWebAuthnSignCount: %v", err)
		}
		got, err := store.WebAuthnCredentialByCredentialID(ctx, credID)
		if err != nil {
			t.Fatalf("WebAuthnCredentialByCredentialID after update: %v", err)
		}
		if got.SignCount != 1 {
			t.Fatalf("SignCount: want 1, got %d", got.SignCount)
		}
		if got.LastUsedAt == nil {
			t.Fatal("LastUsedAt should be set after UpdateWebAuthnSignCount")
		}
	})

	t.Run("ReplayDetected", func(t *testing.T) {
		// Presenting the same or lower count must be rejected.
		err := store.UpdateWebAuthnSignCount(ctx, credID, 1, time.Now())
		if !errors.Is(err, theauth.ErrReplayDetected) {
			t.Fatalf("want ErrReplayDetected for non-increasing count, got %v", err)
		}
	})

	t.Run("BackupFlagsNilUntilRecorded", func(t *testing.T) {
		// The credential above was inserted with no backup flags, so both
		// must read back nil ("never recorded"), distinct from a stored false.
		got, err := store.WebAuthnCredentialByCredentialID(ctx, credID)
		if err != nil {
			t.Fatalf("WebAuthnCredentialByCredentialID: %v", err)
		}
		if got.BackupEligible != nil || got.BackupState != nil {
			t.Fatalf("unrecorded backup flags must be nil, got BE=%v BS=%v", got.BackupEligible, got.BackupState)
		}
	})

	t.Run("ReconcileBackupFlags", func(t *testing.T) {
		if err := store.UpdateWebAuthnBackupFlags(ctx, credID, true, true); err != nil {
			t.Fatalf("UpdateWebAuthnBackupFlags: %v", err)
		}
		got, err := store.WebAuthnCredentialByCredentialID(ctx, credID)
		if err != nil {
			t.Fatalf("WebAuthnCredentialByCredentialID after reconcile: %v", err)
		}
		if got.BackupEligible == nil || !*got.BackupEligible {
			t.Fatalf("BackupEligible: want &true, got %v", got.BackupEligible)
		}
		if got.BackupState == nil || !*got.BackupState {
			t.Fatalf("BackupState: want &true, got %v", got.BackupState)
		}
	})

	t.Run("BackupFlagsRoundTripOnInsert", func(t *testing.T) {
		// A credential registered after the fix stores explicit flags; a
		// genuine non-backup-eligible authenticator round-trips as false, NOT
		// nil, so it stays distinguishable from an unrecorded legacy row.
		be, bs := false, false
		c := theauth.WebAuthnCredential{
			ID:             newID(),
			UserID:         uid,
			CredentialID:   []byte("second-credential-id-bytes-87654321"),
			PublicKey:      pubKey,
			SignCount:      0,
			Transports:     []string{"hybrid"},
			Name:           "Non-Synced Key",
			CreatedAt:      time.Now(),
			BackupEligible: &be,
			BackupState:    &bs,
		}
		if _, err := store.InsertWebAuthnCredential(ctx, c); err != nil {
			t.Fatalf("InsertWebAuthnCredential (with flags): %v", err)
		}
		got, err := store.WebAuthnCredentialByCredentialID(ctx, c.CredentialID)
		if err != nil {
			t.Fatalf("WebAuthnCredentialByCredentialID (with flags): %v", err)
		}
		if got.BackupEligible == nil || *got.BackupEligible {
			t.Fatalf("BackupEligible: want &false, got %v", got.BackupEligible)
		}
		if got.BackupState == nil || *got.BackupState {
			t.Fatalf("BackupState: want &false, got %v", got.BackupState)
		}
	})

	t.Run("DeleteCrossUserMiss", func(t *testing.T) {
		otherUID := newID()
		if _, err := store.CreateUser(ctx, theauth.User{
			ID:        otherUID,
			Email:     "webauthn-other@storagetest.example",
			CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("CreateUser other: %v", err)
		}
		// Delete scoped to wrong user should not leak row existence.
		err := store.DeleteWebAuthnCredential(ctx, credRowID, otherUID)
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("cross-user delete: want ErrNotFound, got %v", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if err := store.DeleteWebAuthnCredential(ctx, credRowID, uid); err != nil {
			t.Fatalf("DeleteWebAuthnCredential: %v", err)
		}
		if _, err := store.WebAuthnCredentialByCredentialID(ctx, credID); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("after delete: want ErrNotFound, got %v", err)
		}
	})
}
