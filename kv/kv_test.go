package kv

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func TestMemoryCache(t *testing.T) {
	ctx := context.Background()
	t.Run("get set delete with ttl", func(t *testing.T) {
		clk := newClock()
		m := NewMemory(WithClock(clk.Now))
		if _, ok, _ := m.Get(ctx, "a"); ok {
			t.Fatal("empty cache returned a value")
		}
		_ = m.Set(ctx, "a", []byte("1"), time.Minute)
		if v, ok, _ := m.Get(ctx, "a"); !ok || string(v) != "1" {
			t.Fatalf("got %q %v", v, ok)
		}
		clk.Advance(time.Minute)
		if _, ok, _ := m.Get(ctx, "a"); ok {
			t.Fatal("expired entry still visible")
		}
		_ = m.Set(ctx, "b", []byte("x"), 0)
		clk.Advance(1000 * time.Hour)
		if _, ok, _ := m.Get(ctx, "b"); !ok {
			t.Fatal("ttl 0 must not expire")
		}
		_ = m.Delete(ctx, "b")
		if _, ok, _ := m.Get(ctx, "b"); ok {
			t.Fatal("deleted entry visible")
		}
	})
	t.Run("returned bytes are copies", func(t *testing.T) {
		m := NewMemory()
		in := []byte("abc")
		_ = m.Set(ctx, "k", in, 0)
		in[0] = 'z'
		v, _, _ := m.Get(ctx, "k")
		v[1] = 'z'
		again, _, _ := m.Get(ctx, "k")
		if string(again) != "abc" {
			t.Fatalf("aliasing: %q", again)
		}
	})
	t.Run("incr keeps the original window", func(t *testing.T) {
		clk := newClock()
		m := NewMemory(WithClock(clk.Now))
		for want := int64(1); want <= 3; want++ {
			clk.Advance(10 * time.Second)
			if got, _ := m.Incr(ctx, "c", time.Minute); got != want {
				t.Fatalf("incr: got %d want %d", got, want)
			}
		}
		clk.Advance(41 * time.Second) // 61s since creation
		if got, _ := m.Incr(ctx, "c", time.Minute); got != 1 {
			t.Fatalf("window should have reset, got %d", got)
		}
	})
	t.Run("max entries evicts the soonest expiring", func(t *testing.T) {
		clk := newClock()
		m := NewMemory(WithClock(clk.Now), WithMaxEntries(2))
		_ = m.Set(ctx, "short", nil, time.Second)
		_ = m.Set(ctx, "long", nil, time.Hour)
		_ = m.Set(ctx, "new", nil, time.Minute)
		if _, ok, _ := m.Get(ctx, "short"); ok {
			t.Fatal("short should have been evicted")
		}
		if _, ok, _ := m.Get(ctx, "long"); !ok {
			t.Fatal("long should remain")
		}
	})
}

func TestReplayCache(t *testing.T) {
	ctx := context.Background()
	clk := newClock()
	m := NewMemory(WithClock(clk.Now))
	cases := []struct {
		name    string
		rc      ReplayCache
		advance time.Duration
		key     string
		want    bool
	}{
		{"first sighting", m, 0, "jti-1", false},
		{"replay inside window", m, time.Second, "jti-1", true},
		{"other key", m, 0, "jti-2", false},
		{"allowed again after ttl", m, time.Minute, "jti-1", false},
		{"cache adapter first", CacheReplay{Cache: m}, 0, "jti-9", false},
		{"cache adapter replay", CacheReplay{Cache: m}, 0, "jti-9", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk.Advance(tc.advance)
			got, err := tc.rc.Seen(ctx, tc.key, time.Minute)
			if err != nil || got != tc.want {
				t.Fatalf("Seen = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	t.Run("exactly one winner under contention", func(t *testing.T) {
		var firsts atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if seen, _ := m.Seen(ctx, "race", time.Hour); !seen {
					firsts.Add(1)
				}
			}()
		}
		wg.Wait()
		if firsts.Load() != 1 {
			t.Fatalf("winners = %d", firsts.Load())
		}
	})
}

func TestRateLimiters(t *testing.T) {
	ctx := context.Background()
	t.Run("memory token bucket", func(t *testing.T) {
		clk := newClock()
		m := NewMemory(WithClock(clk.Now))
		steps := []struct {
			advance time.Duration
			key     string
			want    bool
		}{
			{0, "ip", true}, {0, "ip", true}, {0, "ip", true},
			{0, "ip", false},                // burst spent
			{0, "other", true},              // independent key
			{10 * time.Second, "ip", false}, // 3/min = one token per 20s
			{10 * time.Second, "ip", true},  // refilled one
			{0, "ip", false},
		}
		for i, s := range steps {
			clk.Advance(s.advance)
			d, err := m.Allow(ctx, s.key, 3, time.Minute)
			if err != nil || d.Allowed != s.want {
				t.Fatalf("step %d: allowed=%v err=%v want %v", i, d.Allowed, err, s.want)
			}
			if !d.Allowed && d.RetryAfter <= 0 {
				t.Fatalf("step %d: missing RetryAfter", i)
			}
		}
	})
	t.Run("memory idle buckets are swept", func(t *testing.T) {
		clk := newClock()
		m := NewMemory(WithClock(clk.Now), WithMaxEntries(2))
		_, _ = m.Allow(ctx, "a", 5, time.Minute)
		_, _ = m.Allow(ctx, "b", 5, time.Minute)
		clk.Advance(2 * time.Minute)
		_, _ = m.Allow(ctx, "c", 5, time.Minute)
		if _, b := m.Len(); b != 1 {
			t.Fatalf("buckets = %d, want 1", b)
		}
	})
	t.Run("window limiter on a cache", func(t *testing.T) {
		clk := newClock()
		m := NewMemory(WithClock(clk.Now))
		l := WindowLimiter{Cache: m, Prefix: "rl:"}
		for i := 1; i <= 4; i++ {
			d, err := l.Allow(ctx, "k", 3, time.Minute)
			if err != nil || d.Allowed != (i <= 3) {
				t.Fatalf("call %d allowed=%v err=%v", i, d.Allowed, err)
			}
		}
		clk.Advance(time.Minute)
		if d, _ := l.Allow(ctx, "k", 3, time.Minute); !d.Allowed {
			t.Fatal("new window must allow")
		}
	})
	t.Run("non-positive policy never blocks", func(t *testing.T) {
		m := NewMemory()
		if d, _ := m.Allow(ctx, "k", 0, time.Minute); !d.Allowed {
			t.Fatal("limit 0 should not block")
		}
	})
}

func TestFromCache(t *testing.T) {
	s := FromCache(NewMemory())
	if s.RateLimiter == nil || s.ReplayCache == nil || s.Cache == nil {
		t.Fatalf("incomplete: %+v", s)
	}
}
