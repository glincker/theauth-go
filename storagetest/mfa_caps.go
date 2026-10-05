package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/storage"
)

// MFACapsStorage is the storage RunMFACaps needs.
type MFACapsStorage interface {
	theauth.UserStorage
	theauth.WebAuthnStorage
	theauth.TOTPStorage
}

// RunMFACaps runs the contract tests for the optional WebAuthnRenameStorage
// and RecoveryCodeStorage capabilities. Each half is skipped when the store
// does not implement it.
func RunMFACaps(t *testing.T, store MFACapsStorage) {
	t.Helper()
	t.Run("WebAuthnRename", func(t *testing.T) { testWebAuthnRename(t, store) })
	t.Run("RecoveryCodes", func(t *testing.T) { testRecoveryCodeCaps(t, store) })
}

func mkUser(t *testing.T, store theauth.UserStorage, email string) theauth.ULID {
	t.Helper()
	id := newID()
	if _, err := store.CreateUser(context.Background(), theauth.User{ID: id, Email: email, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return id
}

func testWebAuthnRename(t *testing.T, store MFACapsStorage) {
	rn, ok := any(store).(theauth.WebAuthnRenameStorage)
	if !ok {
		t.Skip("store does not implement WebAuthnRenameStorage")
	}
	ctx := context.Background()
	owner := mkUser(t, store, "rename-owner@storagetest.example")
	other := mkUser(t, store, "rename-other@storagetest.example")
	cred, err := store.InsertWebAuthnCredential(ctx, theauth.WebAuthnCredential{
		ID: newID(), UserID: owner, CredentialID: []byte("rename-cred"), PublicKey: []byte("pk"),
		AAGUID: make([]byte, 16), Name: "old", CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("InsertWebAuthnCredential: %v", err)
	}
	tests := []struct {
		name    string
		id      theauth.ULID
		user    theauth.ULID
		newName string
		wantErr error
		want    string
	}{
		{"owner renames", cred.ID, owner, "new name", nil, "new name"},
		{"other user cannot rename", cred.ID, other, "hijack", storage.ErrNotFound, "new name"},
		{"unknown id", newID(), owner, "x", storage.ErrNotFound, "new name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := rn.RenameWebAuthnCredential(ctx, tc.id, tc.user, tc.newName)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			creds, err := store.WebAuthnCredentialsByUserID(ctx, owner)
			if err != nil || len(creds) != 1 || creds[0].Name != tc.want {
				t.Fatalf("stored name = %+v (%v), want %q", creds, err, tc.want)
			}
		})
	}
}

func testRecoveryCodeCaps(t *testing.T, store MFACapsStorage) {
	rc, ok := any(store).(theauth.RecoveryCodeStorage)
	if !ok {
		t.Skip("store does not implement RecoveryCodeStorage")
	}
	ctx := context.Background()
	uid := mkUser(t, store, "recovery-owner@storagetest.example")
	bystander := mkUser(t, store, "recovery-bystander@storagetest.example")

	batch := func(user theauth.ULID, plain ...string) []theauth.RecoveryCode {
		out := make([]theauth.RecoveryCode, 0, len(plain))
		for _, p := range plain {
			h, err := crypto.HashRecoveryCode(p)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, theauth.RecoveryCode{ID: newID(), UserID: user, CodeHash: h, CreatedAt: time.Now()})
		}
		return out
	}
	count := func(user theauth.ULID) int {
		n, err := rc.CountUnusedRecoveryCodes(ctx, user)
		if err != nil {
			t.Fatalf("CountUnusedRecoveryCodes: %v", err)
		}
		return n
	}

	if err := rc.ReplaceRecoveryCodes(ctx, bystander, batch(bystander, "bystander-1")); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name  string
		do    func() error
		want  int
		login string
	}{
		{"empty", func() error { return nil }, 0, ""},
		{"first batch", func() error { return rc.ReplaceRecoveryCodes(ctx, uid, batch(uid, "aaa-1", "aaa-2", "aaa-3")) }, 3, "aaa-1"},
		{"consume lowers count", func() error { return store.ConsumeRecoveryCode(ctx, uid, "aaa-2", time.Now()) }, 2, ""},
		{"replace drops old", func() error { return rc.ReplaceRecoveryCodes(ctx, uid, batch(uid, "bbb-1", "bbb-2")) }, 2, "bbb-1"},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			if err := s.do(); err != nil {
				t.Fatal(err)
			}
			if got := count(uid); got != s.want {
				t.Fatalf("count = %d, want %d", got, s.want)
			}
		})
	}
	if err := store.ConsumeRecoveryCode(ctx, uid, "aaa-1", time.Now()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("replaced code must be gone, got %v", err)
	}
	if err := store.ConsumeRecoveryCode(ctx, uid, "bbb-1", time.Now()); err != nil {
		t.Fatalf("new code must work: %v", err)
	}
	if count(bystander) != 1 {
		t.Fatal("replace must not touch other users")
	}
}
