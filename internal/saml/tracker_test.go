package saml

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/kv"
)

func trackers(t *testing.T) map[string]func() RequestTracker {
	t.Helper()
	return map[string]func() RequestTracker{
		"memory": func() RequestTracker { return NewMemoryTracker() },
		"kv":     func() RequestTracker { return NewKVTracker(kv.NewMemory()) },
	}
}

func TestTrackerConsume(t *testing.T) {
	ctx := context.Background()
	for name, mk := range trackers(t) {
		t.Run(name, func(t *testing.T) {
			tr := mk()
			if err := tr.Issue(ctx, "conn-1", "id-1", "/home", time.Minute); err != nil {
				t.Fatal(err)
			}
			tests := []struct {
				name        string
				conn, relay string
				id          string
				want        bool
			}{
				{"other connection", "conn-2", "", "id-1", false},
				{"other relay state", "conn-1", "/evil", "id-1", false},
				{"unknown id", "conn-1", "", "id-x", false},
				{"matching, relay checked", "conn-1", "/home", "id-1", true},
				{"second use", "conn-1", "/home", "id-1", false},
			}
			for _, tc := range tests {
				got, err := tr.Consume(ctx, tc.conn, tc.id, tc.relay)
				if err != nil || got != tc.want {
					t.Fatalf("%s: got %v err %v, want %v", tc.name, got, err, tc.want)
				}
			}
		})
	}
}

func TestTrackerExpiry(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryTracker()
	now := time.Now()
	m.now = func() time.Time { return now }
	_ = m.Issue(ctx, "c", "id", "", time.Minute)
	now = now.Add(2 * time.Minute)
	if ok, _ := m.Consume(ctx, "c", "id", ""); ok {
		t.Fatal("expired request must not be consumable")
	}
}

func TestTrackerConcurrentConsumeSingleWinner(t *testing.T) {
	ctx := context.Background()
	for name, mk := range trackers(t) {
		t.Run(name, func(t *testing.T) {
			tr := mk()
			if err := tr.Issue(ctx, "c", "id", "", time.Minute); err != nil {
				t.Fatal(err)
			}
			var wins atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if ok, err := tr.Consume(ctx, "c", "id", ""); err == nil && ok {
						wins.Add(1)
					}
				}()
			}
			wg.Wait()
			if got := wins.Load(); got != 1 {
				t.Fatalf("winners = %d, want 1", got)
			}
		})
	}
}

func TestTrackerSeenAssertionSingleWinner(t *testing.T) {
	ctx := context.Background()
	for name, mk := range trackers(t) {
		t.Run(name, func(t *testing.T) {
			tr := mk()
			var fresh atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if dup, err := tr.SeenAssertion(ctx, "c", "a1", time.Minute); err == nil && !dup {
						fresh.Add(1)
					}
				}()
			}
			wg.Wait()
			if got := fresh.Load(); got != 1 {
				t.Fatalf("first-seen count = %d, want 1", got)
			}
		})
	}
}

func TestKVTrackerStoresNoRawIDs(t *testing.T) {
	ctx := context.Background()
	c := kv.NewMemory()
	tr := NewKVTracker(c)
	_ = tr.Issue(ctx, "conn", "raw-request-id", "", time.Minute)
	if _, ok, _ := c.Get(ctx, authnKeyPrefix+"req:raw-request-id"); ok {
		t.Fatal("request id must be digested in the key")
	}
	if _, ok, _ := c.Get(ctx, reqKey("raw-request-id")); !ok {
		t.Fatal("record missing under namespaced key")
	}
}
