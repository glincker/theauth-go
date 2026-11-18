package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/iot/mqttauth"
)

var _ mqttauth.PurgeBroadcaster = (*PurgeBroadcaster)(nil)

type purgeSink struct {
	mu  sync.Mutex
	ids []string
}

func (s *purgeSink) add(id string) {
	s.mu.Lock()
	s.ids = append(s.ids, id)
	s.mu.Unlock()
}

func (s *purgeSink) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ids...)
}

func waitPurges(t *testing.T, s *purgeSink, want []string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := s.snapshot()
		if len(got) == len(want) {
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("purges = %v, want %v", got, want)
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("purges = %v, want %v", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestPurgeBroadcasterListenNotify runs two subscribers (two replicas) and one publisher over a
// real Postgres. Two subscribers need two pooled connections, plus one for Publish.
func TestPurgeBroadcasterListenNotify(t *testing.T) {
	pool := testPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	channel := "theauth_purge_test_" + time.Now().Format("150405.000000")[7:]
	b := NewPurgeBroadcaster(pool, channel)

	var a, c purgeSink
	done := make(chan error, 2)
	go func() { done <- b.Subscribe(ctx, a.add) }()
	go func() { done <- b.Subscribe(ctx, c.add) }()
	// LISTEN is registered once the connections are busy: wait until Postgres sees both.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int
		err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE query LIKE 'LISTEN %' AND query LIKE '%' || $1 || '%'`, channel).Scan(&n)
		if err == nil && n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("listeners not up: %d %v", n, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := b.Publish(ctx, "01J00000000000000000000001"); err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(ctx, ""); err != nil {
		t.Fatal(err)
	}
	want := []string{"01J00000000000000000000001", ""}
	waitPurges(t, &a, want)
	waitPurges(t, &c, want)

	// Another channel is not heard.
	other := NewPurgeBroadcaster(pool, channel+"_other")
	if err := other.Publish(ctx, "elsewhere"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := a.snapshot(); len(got) != 2 {
		t.Fatalf("heard a foreign channel: %v", got)
	}

	cancel()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Subscribe returned %v on cancel", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Subscribe did not return after cancel")
		}
	}
}

// TestPurgeBroadcasterReconnectPurgesAll kills the listener's backend. The subscriber must listen
// again and report an empty ID, because notifications sent meanwhile are lost.
func TestPurgeBroadcasterReconnectPurgesAll(t *testing.T) {
	pool := testPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	channel := "theauth_purge_gap_" + time.Now().Format("150405.000000")[7:]
	b := NewPurgeBroadcaster(pool, channel)
	var s purgeSink
	done := make(chan error, 1)
	go func() { done <- b.Subscribe(ctx, s.add) }()

	listening := func() int {
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE query LIKE 'LISTEN %' AND query LIKE '%' || $1 || '%'`, channel).Scan(&n)
		return n
	}
	deadline := time.Now().Add(5 * time.Second)
	for listening() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("listener not up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := pool.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query LIKE 'LISTEN %' AND query LIKE '%' || $1 || '%' AND pid <> pg_backend_pid()`, channel); err != nil {
		t.Fatal(err)
	}
	waitPurges(t, &s, []string{""})
	// The new connection works.
	deadline = time.Now().Add(5 * time.Second)
	for listening() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("listener did not come back")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := b.Publish(ctx, "after"); err != nil {
		t.Fatal(err)
	}
	waitPurges(t, &s, []string{"", "after"})
	cancel()
	<-done
}
