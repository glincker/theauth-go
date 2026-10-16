package storagetest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// PushedRequestStorage is the persistence behind RFC 9126 pushed authorization
// requests (the internal PAR storage interface, restated for adapters).
type PushedRequestStorage interface {
	InsertPushedRequest(ctx context.Context, requestURI string, payload []byte, expiresAt time.Time) error
	ConsumePushedRequest(ctx context.Context, requestURI string) ([]byte, error)
}

// RunPushedRequests runs the pushed authorization request contract tests:
// single use consumption, expiry and a one-winner race.
func RunPushedRequests(t *testing.T, store PushedRequestStorage) {
	t.Helper()
	t.Run("PushedRequests", func(t *testing.T) { testPushedRequests(t, store) })
}

func testPushedRequests(t *testing.T, store PushedRequestStorage) {
	ctx := context.Background()
	suffix := newID().String()
	uri := func(n string) string { return "urn:ietf:params:oauth:request_uri:" + n + suffix }

	t.Run("ConsumeOnce", func(t *testing.T) {
		payload := []byte(`{"client_id":"c1","scope":"openid"}`)
		if err := store.InsertPushedRequest(ctx, uri("a"), payload, time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := store.ConsumePushedRequest(ctx, uri("a"))
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("first consume: %q %v", got, err)
		}
		if _, err := store.ConsumePushedRequest(ctx, uri("a")); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("second consume: want ErrStorageNotFound, got %v", err)
		}
	})

	t.Run("UnknownIsNotFound", func(t *testing.T) {
		if _, err := store.ConsumePushedRequest(ctx, uri("never")); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("want ErrStorageNotFound, got %v", err)
		}
	})

	t.Run("ExpiredIsNotFound", func(t *testing.T) {
		if err := store.InsertPushedRequest(ctx, uri("exp"), []byte(`{}`), time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ConsumePushedRequest(ctx, uri("exp")); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("want ErrStorageNotFound, got %v", err)
		}
	})

	t.Run("OneWinner", func(t *testing.T) {
		if err := store.InsertPushedRequest(ctx, uri("race"), []byte(`{"x":1}`), time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := store.ConsumePushedRequest(ctx, uri("race")); err == nil {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("winners = %d, want 1", wins.Load())
		}
	})
}
