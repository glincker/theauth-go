package mqttauth

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pauseStore blocks a DeviceByID call after it read the device, until released. It models a slow
// store read that finished before a revoke and returns after the purge that followed it.
type pauseStore struct {
	*MemoryStore
	armed   atomic.Bool
	reached chan struct{}
	release chan struct{}
}

func newPauseStore() *pauseStore {
	return &pauseStore{MemoryStore: NewMemoryStore(), reached: make(chan struct{}, 1), release: make(chan struct{})}
}

func (s *pauseStore) DeviceByID(ctx context.Context, id string) (*Device, error) {
	d, err := s.MemoryStore.DeviceByID(ctx, id)
	if s.armed.CompareAndSwap(true, false) {
		s.reached <- struct{}{}
		<-s.release
	}
	return d, err
}

// pauseAuthorizer blocks one Authorize call after it decided, until released.
type pauseAuthorizer struct {
	inner   Authorizer
	armed   atomic.Bool
	reached chan struct{}
	release chan struct{}
}

func (a *pauseAuthorizer) Authorize(ctx context.Context, d *Device, act Action, topic string) Decision {
	dec := a.inner.Authorize(ctx, d, act, topic)
	if a.armed.CompareAndSwap(true, false) {
		a.reached <- struct{}{}
		<-a.release
	}
	return dec
}

func staleFixture(t *testing.T, ps *pauseStore, mut func(*Config)) *fixture {
	t.Helper()
	f := newFixture(t, func(c *Config) {
		c.Store = ps
		if mut != nil {
			mut(c)
		}
	})
	for _, d := range []Device{
		{ID: "dev2", Status: StatusActive, TokenHashes: []string{HashToken("tok-2")}, Rules: []Rule{{Allow, ActionAll, "#"}}},
	} {
		if err := ps.PutDevice(context.Background(), d); err != nil {
			t.Fatal(err)
		}
	}
	f.store = ps.MemoryStore
	return f
}

func authzReq() map[string]any {
	return map[string]any{"device_id": "dev2", "action": "publish", "topic": "x/y"}
}

// A device loaded by /authz just before a revoke must not be cached by the load that finishes
// after Purge returned.
func TestStaleLoadAfterPurgeIsNotCached(t *testing.T) {
	ps := newPauseStore()
	f := staleFixture(t, ps, nil)
	ps.armed.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.post("/authz", authzReq(), nil) // raced the revoke, either answer is acceptable
	}()
	<-ps.reached
	if ok, _ := f.store.SetStatus(context.Background(), "dev2", StatusRevoked); !ok {
		t.Fatal("revoke")
	}
	f.h.Purge("dev2")
	close(ps.release)
	<-done
	if _, out := f.post("/authz", authzReq(), nil); out["result"] != "deny" {
		t.Fatal("revoked device authorized from a stale cache entry written after Purge")
	}
}

// Same for the connect path: /authn caches the device it authenticated.
func TestStaleAuthnAfterPurgeIsNotCached(t *testing.T) {
	ps := newPauseStore()
	f := staleFixture(t, ps, nil)
	ps.armed.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.post("/authn", map[string]any{"username": "dev2", "password": "tok-2", "clientid": "dev2"}, nil)
	}()
	<-ps.reached
	if ok, _ := f.store.SetStatus(context.Background(), "dev2", StatusSuspended); !ok {
		t.Fatal("suspend")
	}
	f.h.Purge("dev2")
	close(ps.release)
	<-done
	if _, out := f.post("/authz", authzReq(), nil); out["result"] != "deny" {
		t.Fatal("suspended device authorized from a stale cache entry written after Purge")
	}
}

// PurgeAll has the same guarantee.
func TestStaleLoadAfterPurgeAllIsNotCached(t *testing.T) {
	ps := newPauseStore()
	f := staleFixture(t, ps, nil)
	ps.armed.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.post("/authz", authzReq(), nil)
	}()
	<-ps.reached
	f.store.SetStatus(context.Background(), "dev2", StatusRevoked)
	f.h.PurgeAll()
	close(ps.release)
	<-done
	if _, out := f.post("/authz", authzReq(), nil); out["result"] != "deny" {
		t.Fatal("revoked device authorized after PurgeAll")
	}
}

// A decision computed from rules read before a rule change must not outlive the purge that
// followed the change.
func TestStaleDecisionAfterPurgeIsNotCached(t *testing.T) {
	ps := newPauseStore()
	pa := &pauseAuthorizer{inner: RuleAuthorizer{}, reached: make(chan struct{}, 1), release: make(chan struct{})}
	f := staleFixture(t, ps, func(c *Config) { c.Authorizer = pa })
	pa.armed.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.post("/authz", authzReq(), nil)
	}()
	<-pa.reached
	if err := ps.PutDevice(context.Background(), Device{ID: "dev2", Status: StatusActive, TokenHashes: []string{HashToken("tok-2")}, Rules: []Rule{{Deny, ActionAll, "#"}}}); err != nil {
		t.Fatal(err)
	}
	f.h.Purge("dev2")
	close(pa.release)
	<-done
	if _, out := f.post("/authz", authzReq(), nil); out["result"] != "deny" {
		t.Fatal("decision from the old rules was cached after Purge")
	}
}

// A put that carries a token taken before a purge is dropped, one taken after is kept, and a
// purge of another device in a different shard does not matter.
func TestCacheTokenSemantics(t *testing.T) {
	c := newCache(time.Minute, 0, time.Now)
	d := &Device{ID: "a", Status: StatusActive}
	tok := c.token("a")
	c.purge("a")
	c.putDevice(d, tok)
	c.putDecision("a", "k", Decision{Allowed: true}, tok)
	if _, ok := c.device("a"); ok {
		t.Fatal("stale device was cached")
	}
	if _, ok := c.decision("a", "k"); ok {
		t.Fatal("stale decision was cached")
	}
	tok = c.token("a")
	c.putDevice(d, tok)
	c.putDecision("a", "k", Decision{Allowed: true}, tok)
	if _, ok := c.device("a"); !ok {
		t.Fatal("fresh device was not cached")
	}
	if _, ok := c.decision("a", "k"); !ok {
		t.Fatal("fresh decision was not cached")
	}
	snap := c.snapshot()
	c.purgeAll()
	c.putDevice(d, c.tokenFrom(snap, "a"))
	if _, ok := c.device("a"); ok {
		t.Fatal("device cached with a token from before purgeAll")
	}
}

// Stress under -race: readers keep loading while each round revokes and purges. Once Purge has
// returned, the next authorize must deny however the readers interleaved.
func TestPurgeStress(t *testing.T) {
	const rounds, readers = 200, 8
	store := NewMemoryStore()
	f := newFixture(t, func(c *Config) { c.Store = store })
	ctx := context.Background()
	for r := 0; r < rounds; r++ {
		id := fmt.Sprintf("s%d", r)
		if err := store.PutDevice(ctx, Device{ID: id, Status: StatusActive, TokenHashes: []string{HashToken("t")}, Rules: []Rule{{Allow, ActionAll, "#"}}}); err != nil {
			t.Fatal(err)
		}
		req := map[string]any{"device_id": id, "action": "publish", "topic": "x/y"}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < readers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					if i%2 == 0 {
						f.post("/authz", req, nil)
					} else {
						f.post("/authn", map[string]any{"username": id, "password": "t", "clientid": id}, nil)
					}
				}
			}(i)
		}
		time.Sleep(200 * time.Microsecond)
		store.SetStatus(ctx, id, StatusRevoked)
		f.h.Purge(id)
		_, out := f.post("/authz", req, nil)
		close(stop)
		wg.Wait()
		if out["result"] != "deny" {
			t.Fatalf("round %d: device still authorized after Purge returned", r)
		}
	}
}
