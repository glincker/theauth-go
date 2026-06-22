package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

func testMagicLinks(t *testing.T, store theauth.Storage) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateAndConsumeOnce", func(t *testing.T) {
		hash := sha256Hash([]byte("ml-one-time"))
		ml := theauth.MagicLink{
			ID:        newID(),
			Email:     "ml-once@storagetest.example",
			TokenHash: hash,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(15 * time.Minute),
		}
		if err := store.CreateMagicLink(ctx, ml); err != nil {
			t.Fatalf("CreateMagicLink: %v", err)
		}

		got, err := store.ConsumeMagicLink(ctx, hash)
		if err != nil {
			t.Fatalf("ConsumeMagicLink (first): %v", err)
		}
		if got.UsedAt == nil {
			t.Fatal("UsedAt should be set after first consume")
		}

		// Second consume must miss.
		if _, err := store.ConsumeMagicLink(ctx, hash); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("second consume: want ErrNotFound, got %v", err)
		}
	})

	t.Run("ExpiredLinkRejected", func(t *testing.T) {
		hash := sha256Hash([]byte("ml-expired"))
		ml := theauth.MagicLink{
			ID:        newID(),
			Email:     "ml-expired@storagetest.example",
			TokenHash: hash,
			CreatedAt: time.Now().Add(-30 * time.Minute),
			ExpiresAt: time.Now().Add(-1 * time.Minute),
		}
		if err := store.CreateMagicLink(ctx, ml); err != nil {
			t.Fatalf("CreateMagicLink: %v", err)
		}

		if _, err := store.ConsumeMagicLink(ctx, hash); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("expired link: want ErrNotFound, got %v", err)
		}
	})

	t.Run("UnknownHashRejected", func(t *testing.T) {
		if _, err := store.ConsumeMagicLink(ctx, sha256Hash([]byte("no-such-ml"))); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("unknown hash: want ErrNotFound, got %v", err)
		}
	})
}
