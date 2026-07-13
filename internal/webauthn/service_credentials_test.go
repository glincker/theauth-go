package webauthn_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/internal/webauthn"
	"github.com/glincker/theauth-go/storage"
	"github.com/glincker/theauth-go/storage/memory"
)

// TestServiceListAndDeleteCredential exercises the two Service methods only
// reachable today via internal/webauthn/handlers: list-by-owner and
// delete-scoped-to-owner. cfg is nil since no real WebAuthn ceremony is
// exercised, only storage passthrough.
func TestServiceListAndDeleteCredential(t *testing.T) {
	store := memory.New()
	svc, err := webauthn.NewService(store, nil, audit.NoopEmitter{}, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx := context.Background()

	owner, err := store.CreateUser(ctx, theauth.User{
		ID: ulid.New(), Email: "owner@h.com",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	cred, err := store.InsertWebAuthnCredential(ctx, theauth.WebAuthnCredential{
		ID: ulid.New(), UserID: owner.ID, CredentialID: []byte("cred-1"),
		PublicKey: []byte("pk"), Name: "laptop", SignCount: 1, CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("InsertWebAuthnCredential: %v", err)
	}

	got, err := svc.ListCredentials(ctx, owner.ID)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(got) != 1 || got[0].ID != cred.ID {
		t.Fatalf("expected 1 credential owned by user, got %+v", got)
	}

	other := ulid.New()
	if err := svc.DeleteCredential(ctx, cred.ID, other); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound deleting another user's credential, got %v", err)
	}

	if err := svc.DeleteCredential(ctx, cred.ID, owner.ID); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	got, err = svc.ListCredentials(ctx, owner.ID)
	if err != nil {
		t.Fatalf("ListCredentials after delete: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no credentials after delete, got %d", len(got))
	}
}
