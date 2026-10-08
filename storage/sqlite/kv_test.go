package sqlite_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/kv"
	"github.com/glincker/theauth-go/v2/kv/sqlkv"
)

type kvClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *kvClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *kvClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newKV(t *testing.T) (*sqlkv.Store, *kvClock) {
	t.Helper()
	clk := &kvClock{t: time.Unix(1_700_000_000, 0)}
	s, err := sqlkv.New(openDB(t), sqlkv.SQLite, sqlkv.WithClock(clk.Now))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("schema is not idempotent: %v", err)
	}
	return s, clk
}

func TestSQLKVCache(t *testing.T) {
	ctx := context.Background()
	t.Run("get set delete expire", func(t *testing.T) {
		s, clk := newKV(t)
		if _, ok, err := s.Get(ctx, "a"); ok || err != nil {
			t.Fatalf("missing: ok=%v err=%v", ok, err)
		}
		if err := s.Set(ctx, "a", []byte("one"), time.Minute); err != nil {
			t.Fatal(err)
		}
		if err := s.Set(ctx, "a", []byte("two"), time.Minute); err != nil {
			t.Fatal(err)
		}
		if v, ok, _ := s.Get(ctx, "a"); !ok || string(v) != "two" {
			t.Fatalf("got %q %v", v, ok)
		}
		clk.Advance(time.Minute)
		if _, ok, _ := s.Get(ctx, "a"); ok {
			t.Fatal("expired row visible")
		}
		if n, err := s.Prune(ctx); err != nil || n != 1 {
			t.Fatalf("prune n=%d err=%v", n, err)
		}
		_ = s.Set(ctx, "b", []byte("x"), 0)
		clk.Advance(10000 * time.Hour)
		if _, ok, _ := s.Get(ctx, "b"); !ok {
			t.Fatal("ttl 0 must persist")
		}
		_ = s.Delete(ctx, "b")
		if _, ok, _ := s.Get(ctx, "b"); ok {
			t.Fatal("delete failed")
		}
	})

	t.Run("setnx reclaims expired holders", func(t *testing.T) {
		s, clk := newKV(t)
		steps := []struct {
			advance time.Duration
			want    bool
		}{{0, true}, {time.Second, false}, {time.Minute, true}, {0, false}}
		for i, st := range steps {
			clk.Advance(st.advance)
			got, err := s.SetNX(ctx, "k", []byte("v"), time.Minute)
			if err != nil || got != st.want {
				t.Fatalf("step %d: got %v err %v want %v", i, got, err, st.want)
			}
		}
	})

	t.Run("incr counts and restarts per window", func(t *testing.T) {
		s, clk := newKV(t)
		for want := int64(1); want <= 3; want++ {
			clk.Advance(5 * time.Second)
			if got, err := s.Incr(ctx, "c", time.Minute); err != nil || got != want {
				t.Fatalf("got %d err %v want %d", got, err, want)
			}
		}
		clk.Advance(time.Minute)
		if got, _ := s.Incr(ctx, "c", time.Minute); got != 1 {
			t.Fatalf("window reset: got %d", got)
		}
	})

	t.Run("replay cache has exactly one winner", func(t *testing.T) {
		s, _ := newKV(t)
		rc := kv.CacheReplay{Cache: s}
		var firsts atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if seen, err := rc.Seen(ctx, "jti", time.Hour); err == nil && !seen {
					firsts.Add(1)
				}
			}()
		}
		wg.Wait()
		if firsts.Load() != 1 {
			t.Fatalf("winners = %d", firsts.Load())
		}
	})

	t.Run("window limiter", func(t *testing.T) {
		s, _ := newKV(t)
		l := kv.FromCache(s).RateLimiter
		for i := 1; i <= 4; i++ {
			d, err := l.Allow(ctx, "ip", 3, time.Minute)
			if err != nil || d.Allowed != (i <= 3) {
				t.Fatalf("call %d: %+v err %v", i, d, err)
			}
		}
	})

	t.Run("rejects hostile table names", func(t *testing.T) {
		if _, err := sqlkv.New(openDB(t), sqlkv.SQLite, sqlkv.WithTable("x; DROP TABLE users")); err == nil {
			t.Fatal("expected error")
		}
	})
}
