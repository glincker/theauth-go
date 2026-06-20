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
