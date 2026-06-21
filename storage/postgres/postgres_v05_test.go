package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage"
)

// TestPostgresSessionAuthLevelDefault confirms a CreateSession through the
// pre-v0.5 code path writes auth_level = 'full' via the DDL default, so
// older callers keep getting full sessions back.
func TestPostgresSessionAuthLevelDefault(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	uid := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: uid, Email: "lvl@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte("lvl"))
	sess, err := s.CreateSession(ctx, theauth.Session{
		ID: ulid.New(), UserID: uid,
		TokenHash: tokenHash[:],
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess.AuthLevel != theauth.AuthLevelFull {
		t.Fatalf("default AuthLevel: got %q want full", sess.AuthLevel)
	}
}

// TestPostgresCreateSessionWithAuthLevelPending exercises the v0.5 path:
// mint pending, then promote via UpdateSessionAuthLevel.
func TestPostgresCreateSessionWithAuthLevelPending(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	uid := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: uid, Email: "pend@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte("pend"))
	sess, err := s.CreateSessionWithAuthLevel(ctx, theauth.Session{
		ID: ulid.New(), UserID: uid,
		TokenHash: tokenHash[:],
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute),
		AuthLevel: theauth.AuthLevelPending2FA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess.AuthLevel != theauth.AuthLevelPending2FA {
		t.Fatalf("pending AuthLevel: got %q", sess.AuthLevel)
	}
	if err := s.UpdateSessionAuthLevel(ctx, sess.ID, theauth.AuthLevelFull); err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionByTokenHash(ctx, tokenHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthLevel != theauth.AuthLevelFull {
		t.Fatalf("after promote: got %q want full", got.AuthLevel)
	}
}

// TestPostgresWebAuthnInsertAndUnique covers happy-path insert plus the
// UNIQUE(credential_id) constraint enforcement.
func TestPostgresWebAuthnInsertAndUnique(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	uid := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: uid, Email: "wa@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	cid := []byte("postgres-cred-1")
	c := theauth.WebAuthnCredential{
		ID: ulid.New(), UserID: uid,
		CredentialID: cid, PublicKey: []byte("pk"),
		AAGUID:    []byte("aaguid-16-bytes!"),
		Name:      "primary",
		CreatedAt: time.Now(),
	}
	got, err := s.InsertWebAuthnCredential(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.CredentialID, cid) {
		t.Fatal("credential_id mismatch on insert returning")
	}
	// Duplicate must fail.
	if _, err := s.InsertWebAuthnCredential(ctx, theauth.WebAuthnCredential{
		ID: ulid.New(), UserID: uid,
		CredentialID: cid, PublicKey: []byte("pk2"),
		AAGUID: []byte("aaguid-16-bytes!"), CreatedAt: time.Now(),
	}); err == nil {
		t.Fatal("duplicate credential_id must fail")
	}
}

// TestPostgresWebAuthnSignCountReplay exercises the atomic UPDATE filter.
// We disambiguate ErrReplayDetected (count not strictly greater) from
// ErrNotFound (missing credential) without leaking either to the wrong path.
func TestPostgresWebAuthnSignCountReplay(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	uid := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: uid, Email: "rp@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	cid := []byte("rp-cred")
	if _, err := s.InsertWebAuthnCredential(ctx, theauth.WebAuthnCredential{
		ID: ulid.New(), UserID: uid,
		CredentialID: cid, PublicKey: []byte("pk"),
		AAGUID: []byte("aaguid-16-bytes!"), SignCount: 7,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.UpdateWebAuthnSignCount(ctx, cid, 8, now); err != nil {
		t.Fatalf("greater count should succeed: %v", err)
	}
	if err := s.UpdateWebAuthnSignCount(ctx, cid, 8, now); !errors.Is(err, theauth.ErrReplayDetected) {
		t.Fatalf("equal count should be ErrReplayDetected; got %v", err)
	}
	if err := s.UpdateWebAuthnSignCount(ctx, []byte("missing"), 9, now); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing credential should be ErrNotFound; got %v", err)
	}
}

// TestPostgresTOTPLifecycle covers upsert (pending), confirm, fetch, and
// the "confirmed secret is preserved against a fresh /enroll/begin" rule.
func TestPostgresTOTPLifecycle(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	uid := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: uid, Email: "tt@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertPendingTOTPSecret(ctx, theauth.TOTPSecret{UserID: uid, SecretEnc: []byte("ct-1"), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	got, err := s.TOTPSecretByUserID(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfirmedAt != nil {
		t.Fatal("pending secret should be unconfirmed")
	}
	if err := s.ConfirmTOTPSecret(ctx, uid, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err = s.TOTPSecretByUserID(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfirmedAt == nil {
		t.Fatal("ConfirmedAt expected after Confirm")
	}
	// A subsequent pending upsert must NOT clobber the confirmed row.
	if err := s.UpsertPendingTOTPSecret(ctx, theauth.TOTPSecret{UserID: uid, SecretEnc: []byte("ct-new"), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	preserved, err := s.TOTPSecretByUserID(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preserved.SecretEnc, []byte("ct-1")) {
		t.Fatalf("confirmed secret was overwritten; got %q", preserved.SecretEnc)
	}
	if err := s.DeleteTOTPSecret(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TOTPSecretByUserID(ctx, uid); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
}

// TestPostgresRecoveryCodeConsume validates the linear-scan verify pattern:
// match wins, reuse loses, cross-user mismatch returns ErrNotFound.
func TestPostgresRecoveryCodeConsume(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	owner := ulid.New()
	other := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: owner, Email: "ro@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, theauth.User{ID: other, Email: "rx@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	codes := []string{"00aa11bb22", "33cc44dd55"}
	stored := make([]theauth.RecoveryCode, 0, len(codes))
	for _, c := range codes {
		h, err := crypto.HashRecoveryCode(c)
		if err != nil {
			t.Fatal(err)
		}
		stored = append(stored, theauth.RecoveryCode{ID: ulid.New(), UserID: owner, CodeHash: h, CreatedAt: time.Now()})
	}
	if err := s.InsertRecoveryCodes(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeRecoveryCode(ctx, owner, "00aa11bb22", time.Now()); err != nil {
		t.Fatalf("first consume should succeed: %v", err)
	}
	if err := s.ConsumeRecoveryCode(ctx, owner, "00aa11bb22", time.Now()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("reuse must fail; got %v", err)
	}
	if err := s.ConsumeRecoveryCode(ctx, other, "33cc44dd55", time.Now()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("cross-user must fail; got %v", err)
	}
	if err := s.ConsumeRecoveryCode(ctx, owner, "33cc44dd55", time.Now()); err != nil {
		t.Fatalf("second valid code should succeed: %v", err)
	}
}
