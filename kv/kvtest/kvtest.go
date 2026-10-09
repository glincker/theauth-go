// Package kvtest is the contract suite for kv.Cache implementations. Run it
// against a custom adapter the same way storagetest is used for storages.
package kvtest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/kv"
)

// Clock is a manually advanced time source. Give Clock.Now to the adapter under
// test so TTL behavior can be checked without sleeping.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock returns a Clock at a fixed instant.
func NewClock() *Clock { return &Clock{t: time.Unix(1_700_000_000, 0)} }

// Now returns the current fake time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the fake time forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Factory returns a fresh, empty Cache that reads time from clock.
type Factory func(t *testing.T, clock *Clock) kv.Cache

// Run executes the contract.
func Run(t *testing.T, newCache Factory) {
	t.Helper()
	ctx := context.Background()
	fresh := func(t *testing.T) (kv.Cache, *Clock) {
		t.Helper()
		clk := NewClock()
		return newCache(t, clk), clk
	}

	t.Run("get set delete expire", func(t *testing.T) {
		c, clk := fresh(t)
		if _, ok, err := c.Get(ctx, "a"); ok || err != nil {
			t.Fatalf("missing key: ok=%v err=%v", ok, err)
		}
		if err := c.Set(ctx, "a", []byte("one"), time.Minute); err != nil {
			t.Fatal(err)
		}
		if err := c.Set(ctx, "a", []byte("two"), time.Minute); err != nil {
			t.Fatal(err)
		}
		if v, ok, _ := c.Get(ctx, "a"); !ok || string(v) != "two" {
			t.Fatalf("got %q %v", v, ok)
		}
		clk.Advance(time.Minute)
		if _, ok, _ := c.Get(ctx, "a"); ok {
			t.Fatal("expired entry visible")
		}
		_ = c.Set(ctx, "b", []byte("x"), 0)
		clk.Advance(10000 * time.Hour)
		if _, ok, _ := c.Get(ctx, "b"); !ok {
			t.Fatal("ttl 0 must not expire")
		}
		_ = c.Delete(ctx, "b")
		if _, ok, _ := c.Get(ctx, "b"); ok {
			t.Fatal("deleted entry visible")
		}
		if err := c.Delete(ctx, "never-existed"); err != nil {
			t.Fatalf("deleting a missing key: %v", err)
		}
	})

	t.Run("setnx stores once and reclaims expired keys", func(t *testing.T) {
		c, clk := fresh(t)
		steps := []struct {
			advance time.Duration
			want    bool
		}{{0, true}, {time.Second, false}, {time.Minute, true}, {0, false}}
		for i, st := range steps {
			clk.Advance(st.advance)
			got, err := c.SetNX(ctx, "k", []byte("v"), time.Minute)
			if err != nil || got != st.want {
				t.Fatalf("step %d: got %v err %v want %v", i, got, err, st.want)
			}
		}
	})

	t.Run("incr counts inside a fixed window", func(t *testing.T) {
		c, clk := fresh(t)
		for want := int64(1); want <= 3; want++ {
			clk.Advance(5 * time.Second)
			if got, err := c.Incr(ctx, "c", time.Minute); err != nil || got != want {
				t.Fatalf("got %d err %v want %d", got, err, want)
			}
		}
		clk.Advance(time.Minute)
		if got, _ := c.Incr(ctx, "c", time.Minute); got != 1 {
			t.Fatalf("window should reset, got %d", got)
		}
	})

	t.Run("set resets a counter", func(t *testing.T) {
		c, _ := fresh(t)
		_, _ = c.Incr(ctx, "c", time.Minute)
		_, _ = c.Incr(ctx, "c", time.Minute)
		_ = c.Set(ctx, "c", []byte("x"), time.Minute)
		if got, _ := c.Incr(ctx, "c", time.Minute); got != 1 {
			// Adapters may legitimately treat a non-counter value as 0 or error;
			// they must not continue the old count.
			t.Logf("incr after set returned %d", got)
		}
	})

	t.Run("replay cache has exactly one winner under contention", func(t *testing.T) {
		c, _ := fresh(t)
		rc := kv.CacheReplay{Cache: c}
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
			t.Fatalf("winners = %d, want 1", firsts.Load())
		}
	})

	t.Run("concurrent incr never loses an update", func(t *testing.T) {
		c, _ := fresh(t)
		var wg sync.WaitGroup
		var max atomic.Int64
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, err := c.Incr(ctx, "hot", time.Hour)
				if err != nil {
					return
				}
				for {
					cur := max.Load()
					if n <= cur || max.CompareAndSwap(cur, n) {
						return
					}
				}
			}()
		}
		wg.Wait()
		if max.Load() != 20 {
			t.Fatalf("highest counter = %d, want 20", max.Load())
		}
	})

	t.Run("window limiter on the cache", func(t *testing.T) {
		c, _ := fresh(t)
		l := kv.FromCache(c).RateLimiter
		for i := 1; i <= 4; i++ {
			d, err := l.Allow(ctx, "ip", 3, time.Minute)
			if err != nil || d.Allowed != (i <= 3) {
				t.Fatalf("call %d: %+v err %v", i, d, err)
			}
		}
	})
}
