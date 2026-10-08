package cimd

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/kv"
)

func TestSharedCacheTier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ts := newTestServer(t, nil)
	doc := Document{
		ClientID:                ts.URL(),
		ClientName:              "Shared",
		RedirectURIs:            []string{"https://example.org/cb"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
	}
	ts.setHandler(serveDoc(doc))
	shared := kv.NewMemory()
	newSvc := func() *Service {
		return NewService(Config{
			TrustPolicy: AllowAnyHTTPS(),
			HTTPClient:  trustingClient(2 * time.Second),
			Cache:       shared,
		}, nil)
	}
	replicaA, replicaB := newSvc(), newSvc()

	if _, err := replicaA.Resolve(ctx, ts.URL()); err != nil {
		t.Fatalf("replica A: %v", err)
	}
	if _, err := replicaB.Resolve(ctx, ts.URL()); err != nil {
		t.Fatalf("replica B: %v", err)
	}
	if got := ts.hits.Load(); got != 1 {
		t.Fatalf("publisher hit %d times, want 1 (second replica should read the shared tier)", got)
	}

	t.Run("invalidate clears the shared tier", func(t *testing.T) {
		replicaA.Invalidate(ts.URL())
		replicaC := newSvc()
		if _, err := replicaC.Resolve(ctx, ts.URL()); err != nil {
			t.Fatal(err)
		}
		if got := ts.hits.Load(); got != 2 {
			t.Fatalf("hits = %d, want 2", got)
		}
	})

	t.Run("a corrupt shared entry is ignored", func(t *testing.T) {
		_ = shared.Set(ctx, sharedKeyPrefix+cacheKey(ts.URL()), []byte(`{"client_id":"https://evil.example/x"}`), time.Minute)
		replicaD := newSvc()
		c, err := replicaD.Resolve(ctx, ts.URL())
		if err != nil || c.ClientID != ts.URL() {
			t.Fatalf("resolve: %v %+v", err, c)
		}
	})
}
