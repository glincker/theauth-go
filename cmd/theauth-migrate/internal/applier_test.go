package internal_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	theauth "github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/cmd/theauth-migrate/internal"
	"github.com/glincker/theauth-go/storage/memory"
)

func sampleBundle() *internal.Bundle {
	now := time.Now().UTC()
	return &internal.Bundle{
		SchemaVersion: "1",
		Source:        "cognito",
		ExportedAt:    now,
		Users: []internal.UserRecord{
			{
				SourceID:              "user-a",
				Email:                 "alice@example.com",
				Name:                  "Alice",
				EmailVerified:         true,
				RequiresPasswordReset: true,
				CreatedAt:             now.Add(-48 * time.Hour),
				UpdatedAt:             now.Add(-1 * time.Hour),
			},
			{
				SourceID:      "user-b",
				Email:         "bob@example.com",
				Name:          "Bob",
				EmailVerified: false,
				CreatedAt:     now.Add(-24 * time.Hour),
				UpdatedAt:     now,
			},
		},
		OAuthAccounts: []internal.OAuthAccount{
			{
				SourceUserID:   "user-b",
				Provider:       "google",
				ProviderUserID: "google-999",
			},
		},
		Passwords: []internal.PasswordRecord{
			// Alice has no hash (Cognito).
		},
	}
}

func TestApplierIntoMemoryStore(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	var out bytes.Buffer

	result, err := internal.ApplyBundle(ctx, st, sampleBundle(), internal.ApplyOptions{Out: &out})
	if err != nil {
		t.Fatalf("ApplyBundle: %v", err)
	}

	if result.UsersInserted != 2 {
		t.Errorf("UsersInserted=%d; want 2", result.UsersInserted)
	}
	if result.UsersDuplicate != 0 {
		t.Errorf("UsersDuplicate=%d; want 0", result.UsersDuplicate)
	}
	if result.OAuthAccountsInserted != 1 {
		t.Errorf("OAuthAccountsInserted=%d; want 1", result.OAuthAccountsInserted)
	}
	if len(result.PasswordResets) != 1 {
		t.Errorf("PasswordResets=%d; want 1 (alice)", len(result.PasswordResets))
	}
	if result.PasswordResets[0].Email != "alice@example.com" {
		t.Errorf("PasswordResets[0].Email=%q; want alice@example.com", result.PasswordResets[0].Email)
	}

	// Verify users are actually in the store.
	alice, err := st.UserByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("UserByEmail(alice): %v", err)
	}
	if alice.Name != "Alice" {
		t.Errorf("alice.Name=%q; want Alice", alice.Name)
	}

	_, err = st.UserByEmail(ctx, "bob@example.com")
	if err != nil {
		t.Fatalf("UserByEmail(bob): %v", err)
	}
}

func TestApplierIdempotent(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	bundle := sampleBundle()

	// First apply.
	r1, err := internal.ApplyBundle(ctx, st, bundle, internal.ApplyOptions{})
	if err != nil {
		t.Fatalf("first ApplyBundle: %v", err)
	}
	if r1.UsersInserted != 2 {
		t.Fatalf("first run: UsersInserted=%d; want 2", r1.UsersInserted)
	}

	// Second apply on the same store must not double-insert.
	r2, err := internal.ApplyBundle(ctx, st, bundle, internal.ApplyOptions{})
	if err != nil {
		t.Fatalf("second ApplyBundle: %v", err)
	}
	if r2.UsersInserted != 0 {
		t.Errorf("second run: UsersInserted=%d; want 0 (all duplicates)", r2.UsersInserted)
	}
	if r2.UsersDuplicate != 2 {
		t.Errorf("second run: UsersDuplicate=%d; want 2", r2.UsersDuplicate)
	}
}

func TestApplierDryRunNoWrites(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	var out bytes.Buffer

	_, err := internal.ApplyBundle(ctx, st, sampleBundle(), internal.ApplyOptions{
		DryRun: true,
		Out:    &out,
	})
	if err != nil {
		t.Fatalf("ApplyBundle (dry-run): %v", err)
	}

	// Nothing should have been written.
	_, err = st.UserByEmail(ctx, "alice@example.com")
	if err == nil || !errors.Is(err, theauth.ErrStorageNotFound) {
		t.Errorf("expected ErrStorageNotFound after dry-run; got err=%v", err)
	}

	// Log output must contain "DRY-RUN".
	if !bytes.Contains(out.Bytes(), []byte("DRY-RUN")) {
		t.Errorf("dry-run output does not contain DRY-RUN; got:\n%s", out.String())
	}
}

func TestApplierInvalidBundle(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	bad := &internal.Bundle{
		SchemaVersion: "99",
		Source:        "",
	}
	_, err := internal.ApplyBundle(ctx, st, bad, internal.ApplyOptions{})
	if err == nil {
		t.Fatal("expected error for invalid bundle; got nil")
	}
}
