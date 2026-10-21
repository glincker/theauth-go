package cimd

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/kv"
)

// pauseTransport blocks one armed round trip after the publisher answered, before the caller reads
// the body. That is the window between a cache miss and the cache store.
type pauseTransport struct {
	inner   http.RoundTripper
	armed   atomic.Bool
	reached chan struct{}
	release chan struct{}
}

func (p *pauseTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := p.inner.RoundTrip(r)
	if p.armed.CompareAndSwap(true, false) {
		p.reached <- struct{}{}
		<-p.release
	}
	return resp, err
}

type raceFixture struct {
	ts  *testServer
	svc *Service
	pt  *pauseTransport
}

func newRaceFixture(t *testing.T, cache kv.Cache) *raceFixture {
	t.Helper()
	ts := newTestServer(t, nil)
	f := &raceFixture{ts: ts}
	f.setName("v1")
	hc := trustingClient(15 * time.Second)
	f.pt = &pauseTransport{inner: hc.Transport, reached: make(chan struct{}, 1), release: make(chan struct{})}
	hc.Transport = f.pt
	f.svc = NewService(Config{TrustPolicy: AllowAnyHTTPS(), HTTPClient: hc, Cache: cache}, nil)
	return f
}

func (f *raceFixture) setName(name string) {
	f.ts.setHandler(serveDoc(Document{
		ClientID:                f.ts.URL(),
		ClientName:              name,
		RedirectURIs:            []string{"https://example.org/cb"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
	}))
}

func (f *raceFixture) name(t *testing.T) string {
	t.Helper()
	c, err := f.svc.Resolve(context.Background(), f.ts.URL())
	if err != nil {
		t.Fatal(err)
	}
	return c.ClientName
}

// startPaused starts a Resolve that stalls after the publisher answered.
func (f *raceFixture) startPaused(t *testing.T) chan struct{} {
	t.Helper()
	f.pt.armed.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = f.svc.Resolve(context.Background(), f.ts.URL())
	}()
	select {
	case <-f.pt.reached:
	case <-time.After(5 * time.Second):
		t.Fatal("fetch never reached the publisher")
	}
	return done
}

func (f *raceFixture) finish(t *testing.T, done chan struct{}) {
	t.Helper()
	close(f.pt.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("paused resolve never finished")
	}
}

// A fetch that read the old document just before the operator changed it and called Invalidate must
// not be cached after Invalidate returned.
func TestResolveStaleFetchAfterInvalidate(t *testing.T) {
	f := newRaceFixture(t, nil)
	done := f.startPaused(t)
	f.setName("v2")
	f.svc.Invalidate(f.ts.URL())
	f.finish(t, done)
	if got := f.name(t); got != "v2" {
		t.Fatalf("served %q after Invalidate, want the fresh document v2", got)
	}
}

// Same window with a shared tier: the stale document must not stay in the shared cache either.
func TestResolveStaleFetchAfterInvalidateSharedTier(t *testing.T) {
	shared := kv.NewMemory()
	f := newRaceFixture(t, shared)
	done := f.startPaused(t)
	f.setName("v2")
	f.svc.Invalidate(f.ts.URL())
	f.finish(t, done)
	if _, ok, _ := shared.Get(context.Background(), sharedKeyPrefix+cacheKey(f.ts.URL())); ok {
		t.Fatal("stale document left in the shared tier after Invalidate")
	}
	if got := f.name(t); got != "v2" {
		t.Fatalf("served %q after Invalidate, want v2", got)
	}
}

// A caller that arrives after Invalidate must not join a fetch that started before it, because that
// fetch may carry the old document.
func TestResolveAfterInvalidateDoesNotJoinOldFlight(t *testing.T) {
	f := newRaceFixture(t, nil)
	done := f.startPaused(t)
	f.setName("v2")
	f.svc.Invalidate(f.ts.URL())
	got := make(chan string, 1)
	go func() {
		c, err := f.svc.Resolve(context.Background(), f.ts.URL())
		if err != nil {
			got <- "error: " + err.Error()
			return
		}
		got <- c.ClientName
	}()
	select {
	case name := <-got:
		if name != "v2" {
			t.Fatalf("late caller got %q, want v2", name)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("late caller joined the stalled pre-Invalidate fetch")
	}
	f.finish(t, done)
}
