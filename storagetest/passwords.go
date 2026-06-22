package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

func testPasswords(t *testing.T, store theauth.Storage) {
	t.Helper()
	ctx := context.Background()

	// Create a user to attach passwords to.
	uid := newID()
	email := "pw-owner@storagetest.example"
	if _, err := store.CreateUser(ctx, theauth.User{
		ID:        uid,
		Email:     email,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	t.Run("EmptyHashBeforeSet", func(t *testing.T) {
		_, hash, err := store.UserByEmailWithPassword(ctx, email)
		if err != nil {
			t.Fatalf("UserByEmailWithPassword: %v", err)
		}
		if hash != "" {
			t.Fatalf("want empty hash before SetUserPassword, got %q", hash)
		}
	})

	t.Run("SetAndGet", func(t *testing.T) {
		const phc = "$argon2id$v=19$m=65536,t=3,p=4$fakesalt$fakehash"
		if err := store.SetUserPassword(ctx, uid, phc); err != nil {
			t.Fatalf("SetUserPassword: %v", err)
		}

		_, hash, err := store.UserByEmailWithPassword(ctx, email)
		if err != nil {
			t.Fatalf("UserByEmailWithPassword after set: %v", err)
		}
		if hash != phc {
			t.Fatalf("hash mismatch: want %q got %q", phc, hash)
		}
	})

	t.Run("SetPasswordUnknownUser", func(t *testing.T) {
		err := store.SetUserPassword(ctx, newID(), "phc-string")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound for unknown user, got %v", err)
		}
	})

	t.Run("UserByEmailWithPasswordNotFound", func(t *testing.T) {
		_, _, err := store.UserByEmailWithPassword(ctx, "nobody@storagetest.example")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound for unknown email, got %v", err)
		}
	})

	t.Run("UserPasswordHashByID", func(t *testing.T) {
		hash, err := store.UserPasswordHashByID(ctx, uid)
		if err != nil {
			t.Fatalf("UserPasswordHashByID: %v", err)
		}
		if hash == "" {
			t.Fatal("UserPasswordHashByID: want non-empty hash after SetUserPassword")
		}
	})

	t.Run("PasswordResetTokenConsumeOnce", func(t *testing.T) {
		h := sha256Hash([]byte("reset-tok-1"))
		rt := theauth.PasswordResetToken{
			ID:        newID(),
			UserID:    uid,
			TokenHash: h,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := store.CreatePasswordResetToken(ctx, rt); err != nil {
			t.Fatalf("CreatePasswordResetToken: %v", err)
		}

		got, err := store.ConsumePasswordResetToken(ctx, h)
		if err != nil {
			t.Fatalf("ConsumePasswordResetToken (first): %v", err)
		}
		if got.UsedAt == nil {
			t.Fatal("UsedAt should be set after first consume")
		}

		if _, err := store.ConsumePasswordResetToken(ctx, h); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("second consume: want ErrNotFound, got %v", err)
		}
	})

	t.Run("PasswordResetTokenExpiredRejected", func(t *testing.T) {
		h := sha256Hash([]byte("reset-tok-expired"))
		rt := theauth.PasswordResetToken{
			ID:        newID(),
			UserID:    uid,
			TokenHash: h,
			CreatedAt: time.Now().Add(-2 * time.Hour),
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		if err := store.CreatePasswordResetToken(ctx, rt); err != nil {
			t.Fatalf("CreatePasswordResetToken: %v", err)
		}

		if _, err := store.ConsumePasswordResetToken(ctx, h); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("expired token: want ErrNotFound, got %v", err)
		}
	})

	t.Run("MovePasswordHash", func(t *testing.T) {
		src := newID()
		dst := newID()
		if _, err := store.CreateUser(ctx, theauth.User{ID: src, Email: "pw-src@storagetest.example", CreatedAt: time.Now()}); err != nil {
			t.Fatalf("CreateUser src: %v", err)
		}
		if _, err := store.CreateUser(ctx, theauth.User{ID: dst, Email: "pw-dst@storagetest.example", CreatedAt: time.Now()}); err != nil {
			t.Fatalf("CreateUser dst: %v", err)
		}

		const phc = "$argon2id$v=19$move-hash"
		if err := store.SetUserPassword(ctx, src, phc); err != nil {
			t.Fatalf("SetUserPassword src: %v", err)
		}

		if err := store.MovePasswordHash(ctx, dst, src); err != nil {
			t.Fatalf("MovePasswordHash: %v", err)
		}

		dstHash, err := store.UserPasswordHashByID(ctx, dst)
		if err != nil {
			t.Fatalf("UserPasswordHashByID dst: %v", err)
		}
		if dstHash != phc {
			t.Fatalf("dst hash: want %q got %q", phc, dstHash)
		}

		srcHash, err := store.UserPasswordHashByID(ctx, src)
		if err != nil {
			t.Fatalf("UserPasswordHashByID src: %v", err)
		}
		if srcHash != "" {
			t.Fatalf("src hash should be empty after move, got %q", srcHash)
		}
	})
}
