package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

func testSessions(t *testing.T, store theauth.Storage) {
	t.Helper()
	ctx := context.Background()

	// Create a user to own sessions.
	userID := newID()
	if _, err := store.CreateUser(ctx, theauth.User{
		ID:        userID,
		Email:     "session-owner@storagetest.example",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	t.Run("CreateAndFetchByTokenHash", func(t *testing.T) {
		hash := sha256Hash([]byte("sess-token-1"))
		sess := theauth.Session{
			ID:        newID(),
			UserID:    userID,
			TokenHash: hash,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		created, err := store.CreateSession(ctx, sess)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if created.AuthLevel != theauth.AuthLevelFull {
			t.Fatalf("default AuthLevel want %q got %q", theauth.AuthLevelFull, created.AuthLevel)
		}

		got, err := store.SessionByTokenHash(ctx, hash)
		if err != nil {
			t.Fatalf("SessionByTokenHash: %v", err)
		}
		if got.ID != sess.ID {
			t.Fatalf("ID mismatch")
		}
	})

	t.Run("RevokeSession", func(t *testing.T) {
		hash := sha256Hash([]byte("sess-token-revoke"))
		sess := theauth.Session{
			ID:        newID(),
			UserID:    userID,
			TokenHash: hash,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if _, err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		if err := store.RevokeSession(ctx, sess.ID); err != nil {
			t.Fatalf("RevokeSession: %v", err)
		}

		got, err := store.SessionByTokenHash(ctx, hash)
		if err != nil {
			t.Fatalf("SessionByTokenHash after revoke: %v", err)
		}
		if got.RevokedAt == nil {
			t.Fatal("RevokedAt should be set after RevokeSession")
		}
	})

	t.Run("RevokeUnknownSession", func(t *testing.T) {
		err := store.RevokeSession(ctx, newID())
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("RevokeUserSessions", func(t *testing.T) {
		uid := newID()
		if _, err := store.CreateUser(ctx, theauth.User{
			ID:        uid,
			Email:     "sess-bulk-revoke@storagetest.example",
			CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		var hashes [][]byte
		for i := 0; i < 3; i++ {
			h := sha256Hash([]byte{byte(i), 0xca, 0xfe})
			hashes = append(hashes, h)
			sess := theauth.Session{
				ID:        newID(),
				UserID:    uid,
				TokenHash: h,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(time.Hour),
			}
			if _, err := store.CreateSession(ctx, sess); err != nil {
				t.Fatalf("CreateSession[%d]: %v", i, err)
			}
		}

		if err := store.RevokeUserSessions(ctx, uid); err != nil {
			t.Fatalf("RevokeUserSessions: %v", err)
		}

		for i, h := range hashes {
			got, err := store.SessionByTokenHash(ctx, h)
			if err != nil {
				t.Fatalf("SessionByTokenHash[%d]: %v", i, err)
			}
			if got.RevokedAt == nil {
				t.Fatalf("session[%d] RevokedAt should be set after RevokeUserSessions", i)
			}
		}
	})

	t.Run("CreateSessionWithAuthLevel", func(t *testing.T) {
		hash := sha256Hash([]byte("sess-pending-2fa"))
		sess := theauth.Session{
			ID:        newID(),
			UserID:    userID,
			TokenHash: hash,
			AuthLevel: theauth.AuthLevelPending2FA,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if _, err := store.CreateSessionWithAuthLevel(ctx, sess); err != nil {
			t.Fatalf("CreateSessionWithAuthLevel: %v", err)
		}

		got, err := store.SessionByTokenHash(ctx, hash)
		if err != nil {
			t.Fatalf("SessionByTokenHash: %v", err)
		}
		if got.AuthLevel != theauth.AuthLevelPending2FA {
			t.Fatalf("AuthLevel want %q got %q", theauth.AuthLevelPending2FA, got.AuthLevel)
		}
	})

	t.Run("UpdateSessionAuthLevel", func(t *testing.T) {
		hash := sha256Hash([]byte("sess-promote"))
		sess := theauth.Session{
			ID:        newID(),
			UserID:    userID,
			TokenHash: hash,
			AuthLevel: theauth.AuthLevelPending2FA,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if _, err := store.CreateSessionWithAuthLevel(ctx, sess); err != nil {
			t.Fatalf("CreateSessionWithAuthLevel: %v", err)
		}

		if err := store.UpdateSessionAuthLevel(ctx, sess.ID, theauth.AuthLevelFull); err != nil {
			t.Fatalf("UpdateSessionAuthLevel: %v", err)
		}

		got, err := store.SessionByTokenHash(ctx, hash)
		if err != nil {
			t.Fatalf("SessionByTokenHash after promote: %v", err)
		}
		if got.AuthLevel != theauth.AuthLevelFull {
			t.Fatalf("AuthLevel want %q got %q after promote", theauth.AuthLevelFull, got.AuthLevel)
		}
	})

	t.Run("SessionNotFound", func(t *testing.T) {
		_, err := store.SessionByTokenHash(ctx, sha256Hash([]byte("no-such-token")))
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
}
