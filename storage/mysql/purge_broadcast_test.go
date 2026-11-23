package mysql_test

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/iot/mqttauth"
	"github.com/glincker/theauth-go/v2/storage/mysql"
)

var _ mqttauth.PurgeBroadcaster = (*mysql.PurgeBroadcaster)(nil)

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

// TestPurgeBroadcasterPolling runs two subscribers (two replicas) and a publisher against a live
// MySQL. Opt in like the store contract: THEAUTH_MYSQL_CONTRACT=1 and THEAUTH_TEST_MYSQL_DSN.
func TestPurgeBroadcasterPolling(t *testing.T) {
	dsn := os.Getenv("THEAUTH_TEST_MYSQL_DSN")
	if os.Getenv("THEAUTH_MYSQL_CONTRACT") != "1" || dsn == "" {
		t.Skip("THEAUTH_MYSQL_CONTRACT and THEAUTH_TEST_MYSQL_DSN not set; skipping live MySQL test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := mysql.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	b := mysql.NewPurgeBroadcaster(db, 20*time.Millisecond, 0)
	// An old row must not be replayed to a new subscriber.
	if err := b.Publish(ctx, "old"); err != nil {
		t.Fatal(err)
	}
	var a, c purgeSink
	done := make(chan error, 2)
	go func() { done <- b.Subscribe(ctx, a.add) }()
	go func() { done <- b.Subscribe(ctx, c.add) }()
	time.Sleep(200 * time.Millisecond)
	for _, id := range []string{"01J00000000000000000000001", ""} {
		if err := b.Publish(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"01J00000000000000000000001", ""}
	waitPurges(t, &a, want)
	waitPurges(t, &c, want)
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
