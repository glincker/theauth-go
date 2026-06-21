package clientauthcache

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestHitMiss(t *testing.T) {
	c := New[int](10, time.Minute)
	if _, ok := c.Get("a", "secret"); ok {
		t.Fatal("empty cache reported hit")
	}
	c.Put("a", "secret", 42)
	v, ok := c.Get("a", "secret")
	if !ok || v != 42 {
		t.Fatalf("expected hit with 42, got hit=%v v=%d", ok, v)
	}
	// Wrong secret on same id must miss without leaking the cached value.
	if _, ok := c.Get("a", "different"); ok {
		t.Fatal("wrong secret returned cache hit")
	}
}

func TestInvalidate(t *testing.T) {
	c := New[int](10, time.Minute)
	c.Put("a", "secret", 1)
	c.Invalidate("a")
	if _, ok := c.Get("a", "secret"); ok {
		t.Fatal("invalidated key still cached")
	}
}

func TestExpiry(t *testing.T) {
	now := time.Now()
	c := New[int](10, time.Minute)
	c.now = func() time.Time { return now }
	c.Put("a", "secret", 1)
	now = now.Add(2 * time.Minute)
	if _, ok := c.Get("a", "secret"); ok {
		t.Fatal("expired entry returned hit")
	}
	if c.Len() != 0 {
		t.Fatalf("expected expired entry evicted, got len=%d", c.Len())
	}
}

func TestLRUEviction(t *testing.T) {
	c := New[int](3, time.Hour)
	c.Put("a", "s", 1)
	c.Put("b", "s", 2)
	c.Put("c", "s", 3)
	// Touch a so it is most-recently-used; b is now LRU.
	if _, ok := c.Get("a", "s"); !ok {
		t.Fatal("missing a")
	}
	c.Put("d", "s", 4)
	if _, ok := c.Get("b", "s"); ok {
		t.Fatal("expected b to be evicted as LRU")
	}
	if c.Len() != 3 {
		t.Fatalf("len=%d want 3", c.Len())
	}
}

func TestBounded(t *testing.T) {
	c := New[int](DefaultMaxEntries, time.Hour)
	for i := 0; i < DefaultMaxEntries*4; i++ {
		c.Put("client-"+strconv.Itoa(i), "s", i)
	}
	if c.Len() > DefaultMaxEntries {
		t.Fatalf("len=%d exceeds bound %d", c.Len(), DefaultMaxEntries)
	}
}

func TestConcurrent(t *testing.T) {
	c := New[int](64, time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "client-" + strconv.Itoa(i%10)
			c.Put(id, "s", i)
			for j := 0; j < 100; j++ {
				_, _ = c.Get(id, "s")
			}
			c.Invalidate(id)
		}(i)
	}
	wg.Wait()
}

func TestReplaceUpdatesDigest(t *testing.T) {
	c := New[int](10, time.Minute)
	c.Put("a", "old", 1)
	c.Put("a", "new", 2)
	if _, ok := c.Get("a", "old"); ok {
		t.Fatal("old digest still authoritative after replace")
	}
	if v, ok := c.Get("a", "new"); !ok || v != 2 {
		t.Fatalf("expected new=2, got ok=%v v=%d", ok, v)
	}
}
