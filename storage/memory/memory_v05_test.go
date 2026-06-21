package memory

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage"
)

// TestMemorySessionAuthLevelDefault confirms CreateSession with an empty
// AuthLevel field stamps the row as AuthLevelFull, mirroring the Postgres
// DDL default. Backward compat: pre-v0.5 callers see no behavior change.
func TestMemorySessionAuthLevelDefault(t *testing.T) {
	s := New()
	ctx := context.Background()
	sess := theauth.Session{ID: ulid.New(), UserID: ulid.New(), TokenHash: []byte("h"), ExpiresAt: time.Now().Add(time.Hour)}
	got, err := s.CreateSession(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthLevel != theauth.AuthLevelFull {
		t.Fatalf("default AuthLevel: got %q want %q", got.AuthLevel, theauth.AuthLevelFull)
	}
}

// TestMemoryCreateSessionWithAuthLevelPending mints a pending session and
// then promotes it via UpdateSessionAuthLevel.
func TestMemoryCreateSessionWithAuthLevelPending(t *testing.T) {
	s := New()
	ctx := context.Background()
	sess := theauth.Session{
		ID: ulid.New(), UserID: ulid.New(), TokenHash: []byte("p"),
		ExpiresAt: time.Now().Add(10 * time.Minute),
		AuthLevel: theauth.AuthLevelPending2FA,
	}
	got, err := s.CreateSessionWithAuthLevel(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthLevel != theauth.AuthLevelPending2FA {
		t.Fatalf("pending AuthLevel not preserved: got %q", got.AuthLevel)
	}
	if err := s.UpdateSessionAuthLevel(ctx, got.ID, theauth.AuthLevelFull); err != nil {
		t.Fatal(err)
	}
	// Re-fetch via token hash to confirm the promotion landed.
	fetched, err := s.SessionByTokenHash(ctx, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if fetched.AuthLevel != theauth.AuthLevelFull {
		t.Fatalf("promoted AuthLevel: got %q want full", fetched.AuthLevel)
	}
}

// TestMemoryWebAuthnInsertAndLookup covers insert, lookup by credential ID,
// and the per-user list. Duplicate credential IDs are refused.
func TestMemoryWebAuthnInsertAndLookup(t *testing.T) {
	s := New()
	ctx := context.Background()
	uid := ulid.New()
	c := theauth.WebAuthnCredential{
		ID:           ulid.New(),
		UserID:       uid,
		CredentialID: []byte("cred-1"),
		PublicKey:    []byte("pk-bytes"),
		AAGUID:       []byte("aaguid-16-bytes!"),
		Name:         "primary",
		CreatedAt:    time.Now(),
	}
	if _, err := s.InsertWebAuthnCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Duplicate credential_id must fail (mirrors Postgres UNIQUE).
	if _, err := s.InsertWebAuthnCredential(ctx, theauth.WebAuthnCredential{
		ID: ulid.New(), UserID: ulid.New(), CredentialID: []byte("cred-1"),
		PublicKey: []byte("other"), AAGUID: []byte("aaguid-16-bytes!"), CreatedAt: time.Now(),
	}); err == nil {
		t.Fatal("duplicate credential_id should fail")
	}
	got, err := s.WebAuthnCredentialByCredentialID(ctx, []byte("cred-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.PublicKey, []byte("pk-bytes")) {
		t.Fatal("public key not persisted")
	}
	list, err := s.WebAuthnCredentialsByUserID(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("user credential list: got %d want 1", len(list))
	}
}

// TestMemoryWebAuthnSignCountReplay verifies the strictly-greater guard.
func TestMemoryWebAuthnSignCountReplay(t *testing.T) {
	s := New()
	ctx := context.Background()
	c := theauth.WebAuthnCredential{
		ID: ulid.New(), UserID: ulid.New(),
		CredentialID: []byte("c-replay"), PublicKey: []byte("pk"),
		AAGUID: []byte("aaguid-16-bytes!"), SignCount: 5,
		CreatedAt: time.Now(),
	}
	if _, err := s.InsertWebAuthnCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// Strictly greater succeeds.
	if err := s.UpdateWebAuthnSignCount(ctx, []byte("c-replay"), 6, now); err != nil {
		t.Fatalf("greater count should succeed: %v", err)
	}
	// Equal fails.
	if err := s.UpdateWebAuthnSignCount(ctx, []byte("c-replay"), 6, now); !errors.Is(err, theauth.ErrReplayDetected) {
		t.Fatalf("equal count: got %v want ErrReplayDetected", err)
	}
	// Lower fails.
	if err := s.UpdateWebAuthnSignCount(ctx, []byte("c-replay"), 3, now); !errors.Is(err, theauth.ErrReplayDetected) {
		t.Fatalf("lower count: got %v want ErrReplayDetected", err)
	}
}

// TestMemoryWebAuthnDelete confirms cross-user delete is refused with the
// same ErrNotFound as missing-row.
func TestMemoryWebAuthnDelete(t *testing.T) {
	s := New()
	ctx := context.Background()
	owner := ulid.New()
	other := ulid.New()
	c := theauth.WebAuthnCredential{
		ID: ulid.New(), UserID: owner,
		CredentialID: []byte("del-1"), PublicKey: []byte("pk"),
		AAGUID: []byte("aaguid-16-bytes!"), CreatedAt: time.Now(),
	}
	if _, err := s.InsertWebAuthnCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteWebAuthnCredential(ctx, c.ID, other); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("cross-user delete must fail with ErrNotFound; got %v", err)
	}
	if err := s.DeleteWebAuthnCredential(ctx, c.ID, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WebAuthnCredentialByCredentialID(ctx, []byte("del-1")); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("credential should be gone after delete; got %v", err)
	}
}

// TestMemoryTOTPLifecycle exercises insert pending, confirm, fetch, delete.
func TestMemoryTOTPLifecycle(t *testing.T) {
	s := New()
	ctx := context.Background()
	uid := ulid.New()
	now := time.Now()
	sec := theauth.TOTPSecret{UserID: uid, SecretEnc: []byte("ciphertext")}
	if err := s.UpsertPendingTOTPSecret(ctx, sec); err != nil {
		t.Fatal(err)
	}
	got, err := s.TOTPSecretByUserID(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfirmedAt != nil {
		t.Fatalf("freshly upserted secret should be unconfirmed")
	}
	if err := s.ConfirmTOTPSecret(ctx, uid, now); err != nil {
		t.Fatal(err)
	}
	got, err = s.TOTPSecretByUserID(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfirmedAt == nil {
		t.Fatalf("expected ConfirmedAt set after Confirm")
	}
	// Upsert against a confirmed secret should leave it intact.
	if err := s.UpsertPendingTOTPSecret(ctx, theauth.TOTPSecret{UserID: uid, SecretEnc: []byte("new-ciphertext")}); err != nil {
		t.Fatal(err)
	}
	preserved, err := s.TOTPSecretByUserID(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preserved.SecretEnc, []byte("ciphertext")) {
		t.Fatalf("confirmed secret must not be overwritten by a fresh pending upsert; got %q", preserved.SecretEnc)
	}
	if err := s.DeleteTOTPSecret(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TOTPSecretByUserID(ctx, uid); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete; got %v", err)
	}
}

// TestMemoryRecoveryCodeConsume covers the verify-then-mark-used path, plus
// reuse rejection and cross-user mismatch (both look identical to the caller).
func TestMemoryRecoveryCodeConsume(t *testing.T) {
	s := New()
	ctx := context.Background()
	uid := ulid.New()
	other := ulid.New()
	codes := []string{"aaaaaaaaaa", "bbbbbbbbbb"}
	stored := make([]theauth.RecoveryCode, 0, len(codes))
	for _, c := range codes {
		h, err := crypto.HashRecoveryCode(c)
		if err != nil {
			t.Fatal(err)
		}
		stored = append(stored, theauth.RecoveryCode{ID: ulid.New(), UserID: uid, CodeHash: h, CreatedAt: time.Now()})
	}
	if err := s.InsertRecoveryCodes(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeRecoveryCode(ctx, uid, "aaaaaaaaaa", time.Now()); err != nil {
		t.Fatalf("first consume should succeed: %v", err)
	}
	if err := s.ConsumeRecoveryCode(ctx, uid, "aaaaaaaaaa", time.Now()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("reuse should fail; got %v", err)
	}
	if err := s.ConsumeRecoveryCode(ctx, other, "bbbbbbbbbb", time.Now()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("cross-user must fail; got %v", err)
	}
	if err := s.ConsumeRecoveryCode(ctx, uid, "bbbbbbbbbb", time.Now()); err != nil {
		t.Fatalf("second valid code should succeed: %v", err)
	}
}
