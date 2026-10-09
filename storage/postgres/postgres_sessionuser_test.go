package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage"
)

func TestPostgresSessionAndUserByTokenHash(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	uid := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: uid, Email: "join@h.com", Name: "Join", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("join-token"))
	want, err := s.CreateSession(ctx, theauth.Session{
		ID: ulid.New(), UserID: uid, TokenHash: hash[:],
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	sess, user, err := s.SessionAndUserByTokenHash(ctx, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID != want.ID || user.ID != uid || user.Email != "join@h.com" || user.Name != "Join" {
		t.Fatalf("got session %v user %+v", sess.ID, user)
	}
	bySession, _ := s.SessionByTokenHash(ctx, hash[:])
	byUser, _ := s.UserByID(ctx, uid)
	if sess.AuthLevel != bySession.AuthLevel || user.Email != byUser.Email {
		t.Fatalf("join result differs from the two-query path: %+v vs %+v", sess, bySession)
	}

	missing := sha256.Sum256([]byte("nope"))
	if _, _, err := s.SessionAndUserByTokenHash(ctx, missing[:]); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unknown token err = %v, want ErrNotFound", err)
	}
}
