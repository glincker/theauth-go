package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage"
	"github.com/glincker/theauth-go/storagetest"
)

func TestCreateUserAndFetchByEmail(t *testing.T) {
	s := New()
	ctx := context.Background()
	u := theauth.User{ID: ulid.New(), Email: "a@b.com", CreatedAt: time.Now()}
	if _, err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := s.UserByEmail(ctx, "a@b.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "a@b.com" {
		t.Fatalf("got email %q", got.Email)
	}
}

func TestUserByEmailNotFound(t *testing.T) {
	s := New()
	_, err := s.UserByEmail(context.Background(), "missing@x.com")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestSessionRoundtripAndRevoke(t *testing.T) {
	s := New()
	ctx := context.Background()
	uid := ulid.New()
	tokenHash := sha256.Sum256([]byte("tok"))
	sess := theauth.Session{
		ID: ulid.New(), UserID: uid,
		TokenHash: tokenHash[:],
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	if _, err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionByTokenHash(ctx, tokenHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.TokenHash, tokenHash[:]) {
		t.Fatal("token hash mismatch")
	}
	if err := s.RevokeSession(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	got2, err := s.SessionByTokenHash(ctx, tokenHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if got2.RevokedAt == nil {
		t.Fatal("expected RevokedAt set")
	}
}

func TestStore_SessionByID(t *testing.T) {
	s := New()
	ctx := context.Background()
	sess := theauth.Session{
		ID:        ulid.New(),
		UserID:    ulid.New(),
		TokenHash: []byte("hash"),
		UserAgent: "test-agent",
		IP:        "127.0.0.1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if _, err := s.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := s.SessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("SessionByID: %v", err)
	}
	if got.ID != sess.ID || got.UserAgent != "test-agent" {
		t.Errorf("SessionByID returned %+v, want ID=%v UserAgent=test-agent", got, sess.ID)
	}

	if _, err := s.SessionByID(ctx, ulid.New()); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("SessionByID(unknown) = %v, want storage.ErrNotFound", err)
	}
}

func TestConsumeMagicLinkOnce(t *testing.T) {
	s := New()
	ctx := context.Background()
	tokenHash := sha256.Sum256([]byte("ml"))
	ml := theauth.MagicLink{
		ID: ulid.New(), Email: "a@b.com",
		TokenHash: tokenHash[:],
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	if err := s.CreateMagicLink(ctx, ml); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumeMagicLink(ctx, tokenHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if got.UsedAt == nil {
		t.Fatal("expected UsedAt set on first consume")
	}
	if _, err := s.ConsumeMagicLink(ctx, tokenHash[:]); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("second consume should miss; got %v", err)
	}
}

func TestMemoryPasswordRoundtrip(t *testing.T) {
	s := New()
	ctx := context.Background()
	uid := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: uid, Email: "pw@h.com", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// Empty hash before set.
	_, ph, err := s.UserByEmailWithPassword(ctx, "pw@h.com")
	if err != nil {
		t.Fatal(err)
	}
	if ph != "" {
		t.Fatalf("expected empty hash; got %q", ph)
	}
	if err := s.SetUserPassword(ctx, uid, "phc-string"); err != nil {
		t.Fatal(err)
	}
	_, ph, err = s.UserByEmailWithPassword(ctx, "pw@h.com")
	if err != nil {
		t.Fatal(err)
	}
	if ph != "phc-string" {
		t.Fatalf("expected hash to persist; got %q", ph)
	}
}

func TestMemorySetPasswordUnknownUser(t *testing.T) {
	s := New()
	err := s.SetUserPassword(context.Background(), ulid.New(), "x")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
}

func TestMemoryUserByEmailWithPasswordNotFound(t *testing.T) {
	s := New()
	_, _, err := s.UserByEmailWithPassword(context.Background(), "nobody@h.com")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
}

func TestMemoryPasswordResetTokenConsume(t *testing.T) {
	s := New()
	ctx := context.Background()
	uid := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: uid, Email: "r@h.com", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("rt"))
	rt := theauth.PasswordResetToken{
		ID: ulid.New(), UserID: uid,
		TokenHash: hash[:],
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.CreatePasswordResetToken(ctx, rt); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumePasswordResetToken(ctx, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	if got.UsedAt == nil {
		t.Fatal("expected UsedAt set on first consume")
	}
	if _, err := s.ConsumePasswordResetToken(ctx, hash[:]); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("second consume should miss; got %v", err)
	}
}

// TestMemoryExpiredMagicLinkNotConsumed verifies the memory adapter matches
// Postgres semantics: expired magic-links are NOT marked used. Without this,
// a single failed/expired verification attempt would burn the link, even
// though the user could still legitimately request a new one.
func TestMemoryExpiredMagicLinkNotConsumed(t *testing.T) {
	s := New()
	ctx := context.Background()
	tokenHash := sha256.Sum256([]byte("expired"))
	ml := theauth.MagicLink{
		ID:        ulid.New(),
		Email:     "expired@h.com",
		TokenHash: tokenHash[:],
		CreatedAt: time.Now().Add(-30 * time.Minute),
		ExpiresAt: time.Now().Add(-1 * time.Minute), // already expired
	}
	if err := s.CreateMagicLink(ctx, ml); err != nil {
		t.Fatal(err)
	}
	// Attempt to consume, should miss without marking the row used.
	if _, err := s.ConsumeMagicLink(ctx, tokenHash[:]); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired link should not be consumable; got %v", err)
	}
	// Verify the underlying row was NOT marked used (defensive: a second
	// attempt with the same hash still misses, and the stored row's UsedAt
	// is still nil).
	s.mu.RLock()
	stored, ok := s.magicLinks[ml.ID]
	s.mu.RUnlock()
	if !ok {
		t.Fatal("magic link row missing from store")
	}
	if stored.UsedAt != nil {
		t.Fatalf("expired link UsedAt should remain nil; got %v", stored.UsedAt)
	}
}

// TestMemoryStoreContract runs the full storagetest contract suite against the
// in-memory backend to verify it satisfies all documented Storage semantics.
func TestMemoryStoreContract(t *testing.T) {
	storagetest.Run(t, New())
}
