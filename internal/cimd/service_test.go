package cimd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testServer wraps an httptest.NewTLSServer plus a counter that lets a
// test assert how many times the AS round-tripped the publisher.
type testServer struct {
	server *httptest.Server
	hits   atomic.Int64
	mu     sync.Mutex
	handle http.HandlerFunc
}

func newTestServer(t *testing.T, h http.HandlerFunc) *testServer {
	t.Helper()
	ts := &testServer{handle: h}
	ts.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.hits.Add(1)
		ts.mu.Lock()
		current := ts.handle
		ts.mu.Unlock()
		if current == nil {
			http.Error(w, "no handler", http.StatusInternalServerError)
			return
		}
		current(w, r)
	}))
	t.Cleanup(ts.server.Close)
	return ts
}

func (ts *testServer) URL() string { return ts.server.URL + "/client" }

func (ts *testServer) setHandler(h http.HandlerFunc) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.handle = h
}

// trustingClient returns an http.Client wired to skip TLS verification so
// httptest.NewTLSServer's self-signed cert is accepted. The Service is
// instantiated with this client in every test that exercises a network
// fetch.
func trustingClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

// serveDoc returns an http handler that writes the JSON marshal of v as
// application/json with HTTP 200.
func serveDoc(v any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(v)
	}
}

func TestResolveFetchSuccess(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, nil)
	doc := Document{
		ClientID:                ts.URL(),
		ClientName:              "Example MCP",
		RedirectURIs:            []string{"https://example.org/cb"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   "files.read files.write",
	}
	ts.setHandler(serveDoc(doc))
	svc := NewService(Config{
		TrustPolicy: AllowAnyHTTPS(),
		HTTPClient:  trustingClient(2 * time.Second),
	}, nil)
	got, err := svc.Resolve(context.Background(), ts.URL())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ClientID != ts.URL() {
		t.Errorf("client_id = %q, want %q", got.ClientID, ts.URL())
	}
	if got.ClientName != "Example MCP" {
		t.Errorf("client_name = %q", got.ClientName)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://example.org/cb" {
		t.Errorf("redirect_uris mismatch: %#v", got.RedirectURIs)
	}
	if got.TokenEndpointAuthMethod != "none" {
		t.Errorf("token_endpoint_auth_method = %q", got.TokenEndpointAuthMethod)
	}
}

func TestResolveCacheHit(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, nil)
	doc := Document{
		ClientID:     ts.URL(),
		RedirectURIs: []string{"https://example.org/cb"},
	}
	ts.setHandler(serveDoc(doc))
	svc := NewService(Config{
		TrustPolicy: AllowAnyHTTPS(),
		CacheTTL:    time.Minute,
		HTTPClient:  trustingClient(2 * time.Second),
	}, nil)
	for i := 0; i < 3; i++ {
		if _, err := svc.Resolve(context.Background(), ts.URL()); err != nil {
			t.Fatalf("Resolve #%d: %v", i, err)
		}
	}
	if got := ts.hits.Load(); got != 1 {
		t.Fatalf("expected 1 upstream hit, got %d", got)
	}
}

func TestResolveCacheExpiry(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, nil)
	doc := Document{
		ClientID:     ts.URL(),
		RedirectURIs: []string{"https://example.org/cb"},
	}
	ts.setHandler(serveDoc(doc))
	svc := NewService(Config{
		TrustPolicy: AllowAnyHTTPS(),
		CacheTTL:    10 * time.Millisecond,
		HTTPClient:  trustingClient(2 * time.Second),
	}, nil)
	if _, err := svc.Resolve(context.Background(), ts.URL()); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	time.Sleep(25 * time.Millisecond)
	if _, err := svc.Resolve(context.Background(), ts.URL()); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if got := ts.hits.Load(); got != 2 {
		t.Fatalf("expected 2 upstream hits after expiry, got %d", got)
	}
}

func TestResolvePolicyDeny(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, serveDoc(Document{
		ClientID:     "https://blocked.example/client",
		RedirectURIs: []string{"https://blocked.example/cb"},
	}))
	svc := NewService(Config{
		TrustPolicy: AllowHTTPSHost("trusted.example"),
		HTTPClient:  trustingClient(2 * time.Second),
	}, nil)
	_, err := svc.Resolve(context.Background(), ts.URL())
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("want ErrPolicyDenied, got %v", err)
	}
	if got := ts.hits.Load(); got != 0 {
		t.Fatalf("expected zero upstream hits when policy denies, got %d", got)
	}
}

func TestResolveTimeout(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	svc := NewService(Config{
		TrustPolicy:  AllowAnyHTTPS(),
		FetchTimeout: 10 * time.Millisecond,
		HTTPClient:   trustingClient(10 * time.Millisecond),
	}, nil)
	_, err := svc.Resolve(context.Background(), ts.URL())
	if !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("want ErrFetchFailed (timeout), got %v", err)
	}
}

func TestResolveOversize(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("a", 256)
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"client_id":"%s","redirect_uris":["https://x/cb"],"padding":"%s"}`,
			"https://x/c", big)
	})
	svc := NewService(Config{
		TrustPolicy:      AllowAnyHTTPS(),
		MaxDocumentBytes: 64,
		HTTPClient:       trustingClient(2 * time.Second),
	}, nil)
	_, err := svc.Resolve(context.Background(), ts.URL())
	if !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("want ErrFetchFailed (oversize), got %v", err)
	}
}

func TestResolveWrongClientID(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, serveDoc(Document{
		// Impersonation: claims to be a different URL than the one
		// being fetched.
		ClientID:     "https://attacker.example/c",
		RedirectURIs: []string{"https://attacker.example/cb"},
	}))
	svc := NewService(Config{
		TrustPolicy: AllowAnyHTTPS(),
		HTTPClient:  trustingClient(2 * time.Second),
	}, nil)
	_, err := svc.Resolve(context.Background(), ts.URL())
	if !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("want ErrInvalidDocument (impersonation), got %v", err)
	}
}

func TestResolveNonHTTPS(t *testing.T) {
	t.Parallel()
	svc := NewService(Config{TrustPolicy: AllowAnyHTTPS()}, nil)
	_, err := svc.Resolve(context.Background(), "http://example.org/c")
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("want ErrPolicyDenied for http://, got %v", err)
	}
}

func TestResolveMissingRedirectURIs(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, nil)
	ts.setHandler(serveDoc(Document{ClientID: ts.URL()}))
	svc := NewService(Config{
		TrustPolicy: AllowAnyHTTPS(),
		HTTPClient:  trustingClient(2 * time.Second),
	}, nil)
	_, err := svc.Resolve(context.Background(), ts.URL())
	if !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("want ErrInvalidDocument (no redirect_uris), got %v", err)
	}
}

func TestResolveMalformedJSON(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{not json`))
	})
	svc := NewService(Config{
		TrustPolicy: AllowAnyHTTPS(),
		HTTPClient:  trustingClient(2 * time.Second),
	}, nil)
	_, err := svc.Resolve(context.Background(), ts.URL())
	if !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("want ErrInvalidDocument (malformed json), got %v", err)
	}
}

func TestResolveContentTypeRejected(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>nope</body></html>"))
	})
	svc := NewService(Config{
		TrustPolicy: AllowAnyHTTPS(),
		HTTPClient:  trustingClient(2 * time.Second),
	}, nil)
	_, err := svc.Resolve(context.Background(), ts.URL())
	if !errors.Is(err, ErrUnsupportedContentType) {
		t.Fatalf("want ErrUnsupportedContentType, got %v", err)
	}
}

func TestResolveHTTPErrorStatus(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	svc := NewService(Config{
		TrustPolicy: AllowAnyHTTPS(),
		HTTPClient:  trustingClient(2 * time.Second),
	}, nil)
	_, err := svc.Resolve(context.Background(), ts.URL())
	if !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("want ErrFetchFailed (404), got %v", err)
	}
}

func TestInvalidateDropsCache(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, nil)
	doc := Document{
		ClientID:     ts.URL(),
		RedirectURIs: []string{"https://example.org/cb"},
	}
	ts.setHandler(serveDoc(doc))
	svc := NewService(Config{
		TrustPolicy: AllowAnyHTTPS(),
		CacheTTL:    time.Minute,
		HTTPClient:  trustingClient(2 * time.Second),
	}, nil)
	if _, err := svc.Resolve(context.Background(), ts.URL()); err != nil {
		t.Fatal(err)
	}
	svc.Invalidate(ts.URL())
	if _, err := svc.Resolve(context.Background(), ts.URL()); err != nil {
		t.Fatal(err)
	}
	if got := ts.hits.Load(); got != 2 {
		t.Fatalf("expected 2 hits after Invalidate, got %d", got)
	}
}

func TestStartStopIdempotent(t *testing.T) {
	t.Parallel()
	svc := NewService(Config{TrustPolicy: DenyAll()}, nil)
	svc.Start()
	svc.Start() // second call is a no-op
	svc.Stop()
	svc.Stop() // second call is a no-op
}

func TestLooksLikeCIMD(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"https://example.org/c", true},
		{"https://example.org", true},
		{"http://example.org/c", false},
		{"client-abc123", false},
		{"", false},
		{"https://", false},
		{"  https://example.org/c", false},
	}
	for _, tc := range cases {
		if got := LooksLikeCIMD(tc.in); got != tc.want {
			t.Errorf("LooksLikeCIMD(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestCacheRaceWithGC exercises concurrent Resolve + GC sweeps to catch
// data races under -race. The test runs short of go test timeout but
// long enough for the GC ticker to fire at least once with a 10ms TTL.
func TestCacheRaceWithGC(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, nil)
	doc := Document{
		ClientID:     ts.URL(),
		RedirectURIs: []string{"https://example.org/cb"},
	}
	ts.setHandler(serveDoc(doc))
	svc := NewService(Config{
		TrustPolicy: AllowAnyHTTPS(),
		CacheTTL:    5 * time.Millisecond,
		HTTPClient:  trustingClient(2 * time.Second),
	}, nil)
	// Drive the GC loop manually instead of relying on the 60s
	// production ticker; the ticker would never fire inside test
	// duration. Equivalent code, much faster.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(2 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				svc.cache.Range(func(k, v any) bool {
					if e, ok := v.(*cacheEntry); ok {
						if now.Sub(e.fetchedAt) >= svc.cfg.CacheTTL {
							svc.cache.Delete(k)
						}
					}
					return true
				})
			}
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := svc.Resolve(context.Background(), ts.URL()); err != nil {
					t.Errorf("Resolve: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-done
}
