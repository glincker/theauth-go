package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

func testUsers(t *testing.T, store theauth.Storage) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateAndFetchByID", func(t *testing.T) {
		u := theauth.User{
			ID:        newID(),
			Email:     "user-byid@storagetest.example",
			Name:      "Test User",
			CreatedAt: time.Now(),
		}
		created, err := store.CreateUser(ctx, u)
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if created.ID != u.ID {
			t.Fatalf("ID mismatch: want %s got %s", u.ID, created.ID)
		}

		got, err := store.UserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("UserByID: %v", err)
		}
		if got.Email != u.Email {
			t.Fatalf("email mismatch: want %q got %q", u.Email, got.Email)
		}
	})

	t.Run("FetchByEmail", func(t *testing.T) {
		u := theauth.User{
			ID:        newID(),
			Email:     "user-byemail@storagetest.example",
			CreatedAt: time.Now(),
		}
		if _, err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		got, err := store.UserByEmail(ctx, u.Email)
		if err != nil {
			t.Fatalf("UserByEmail: %v", err)
		}
		if got.ID != u.ID {
			t.Fatalf("ID mismatch: want %s got %s", u.ID, got.ID)
		}
	})

	t.Run("NotFoundByID", func(t *testing.T) {
		_, err := store.UserByID(ctx, newID())
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("NotFoundByEmail", func(t *testing.T) {
		_, err := store.UserByEmail(ctx, "missing@storagetest.example")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("MarkEmailVerified", func(t *testing.T) {
		u := theauth.User{
			ID:        newID(),
			Email:     "verify@storagetest.example",
			CreatedAt: time.Now(),
		}
		if _, err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		if err := store.MarkEmailVerified(ctx, u.ID); err != nil {
			t.Fatalf("MarkEmailVerified: %v", err)
		}

		got, err := store.UserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("UserByID after verify: %v", err)
		}
		if got.EmailVerifiedAt == nil {
			t.Fatal("EmailVerifiedAt should be set after MarkEmailVerified")
		}
	})

	t.Run("MarkEmailVerifiedUnknownUser", func(t *testing.T) {
		err := store.MarkEmailVerified(ctx, newID())
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound for unknown user, got %v", err)
		}
	})
}
