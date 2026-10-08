package as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/safehttp"
)

// testJWKSDocument returns a JWKS document holding one P-256 key with the given kid.
func testJWKSDocument(t *testing.T, kid string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(map[string]any{"keys": []any{map[string]any{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
		"x": base64.RawURLEncoding.EncodeToString(priv.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(priv.Y.FillBytes(make([]byte, 32))),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// jwksTestServer serves h and counts requests.
func jwksTestServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func serveBody(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

// devFetcher returns a fetcher allowed to reach loopback http servers.
func devFetcher(cfg JWTBearerConfig) *jwksFetcher {
	cfg.AllowPrivateJWKSNetworks = true
	return newJWKSFetcher(&cfg)
}

func TestJWKSFetcherBlocksNonPublicDestinations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		url  string
	}{
		{"loopback", "https://127.0.0.1:9/jwks"},
		{"private 10/8", "https://10.0.0.1/jwks"},
		{"aws metadata v4", "https://169.254.169.254/latest/meta-data"},
		{"aws metadata v6", "https://[fd00:ec2::254]/latest/meta-data"},
		{"ipv4 mapped loopback", "https://[::ffff:127.0.0.1]:9/jwks"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJWKSFetcher(nil)
			_, err := f.Fetch(context.Background(), tc.url)
			if !errors.Is(err, safehttp.ErrBlockedAddress) {
				t.Fatalf("err = %v, want ErrBlockedAddress", err)
			}
			if f.size() != 0 {
				t.Fatal("failed fetch was cached")
			}
		})
	}
}

func TestJWKSFetcherDefaultRefusesLoopbackServer(t *testing.T) {
	t.Parallel()
	srv, hits := jwksTestServer(t, serveBody([]byte(`{"keys":[]}`)))
	// A TLS-less server would fail the https rule first, so point an https
	// URL at the same loopback listener.
	u := strings.Replace(srv.URL, "http://", "https://", 1) + "/jwks"
	_, err := newJWKSFetcher(nil).Fetch(context.Background(), u)
	if !errors.Is(err, safehttp.ErrBlockedAddress) {
		t.Fatalf("err = %v, want ErrBlockedAddress", err)
	}
	if hits.Load() != 0 {
		t.Fatal("loopback server was contacted")
	}
}

func TestJWKSFetcherRefusesRebindingResolver(t *testing.T) {
	t.Parallel()
	srv, hits := jwksTestServer(t, serveBody([]byte(`{"keys":[]}`)))
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: time.Second, Control: safehttp.GuardedControl(false)}
	client := safehttp.ClientWithDialer(time.Second, dialer)
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}
	f := newJWKSFetcher(&JWTBearerConfig{JWKSHTTPClient: client})
	_, err = f.Fetch(context.Background(), "https://rebind.example:"+port+"/jwks")
	if !errors.Is(err, safehttp.ErrBlockedAddress) {
		t.Fatalf("err = %v, want ErrBlockedAddress", err)
	}
	if hits.Load() != 0 {
		t.Fatal("rebound server was contacted")
	}
}

func TestJWKSFetcherURLScheme(t *testing.T) {
	t.Parallel()
	srv, _ := jwksTestServer(t, serveBody([]byte(`{"keys":[]}`)))
	tests := []struct {
		name         string
		allowPrivate bool
		url          string
		wantErr      error
	}{
		{"http rejected by default", false, srv.URL + "/jwks", ErrJWKSInsecureURL},
		{"ftp rejected even in dev", true, "ftp://example.com/jwks", ErrJWKSInsecureURL},
		{"http allowed in dev", true, srv.URL + "/jwks", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJWKSFetcher(&JWTBearerConfig{AllowPrivateJWKSNetworks: tc.allowPrivate})
			_, err := f.Fetch(context.Background(), tc.url)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestJWKSFetcherRedirectNotFollowed(t *testing.T) {
	t.Parallel()
	target, targetHits := jwksTestServer(t, serveBody([]byte(`{"keys":[]}`)))
	srv, _ := jwksTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	})
	f := devFetcher(JWTBearerConfig{})
	_, err := f.Fetch(context.Background(), srv.URL+"/jwks")
	if !errors.Is(err, ErrJWKSStatus) {
		t.Fatalf("err = %v, want ErrJWKSStatus", err)
	}
	if targetHits.Load() != 0 {
		t.Fatal("redirect target was contacted")
	}
}

func TestJWKSFetcherNon200NotCached(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusNoContent, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			var fail atomic.Bool
			fail.Store(true)
			doc := testJWKSDocument(t, "k1")
			srv, hits := jwksTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if fail.Load() {
					w.WriteHeader(status)
					return
				}
				serveBody(doc)(w, r)
			})
			f := devFetcher(JWTBearerConfig{})
			if _, err := f.Fetch(context.Background(), srv.URL); !errors.Is(err, ErrJWKSStatus) {
				t.Fatalf("err = %v, want ErrJWKSStatus", err)
			}
			fail.Store(false)
			keys, err := f.Fetch(context.Background(), srv.URL)
			if err != nil || len(keys) != 1 {
				t.Fatalf("recovery fetch: keys=%d err=%v", len(keys), err)
			}
			if hits.Load() != 2 {
				t.Fatalf("hits = %d, want 2 (negative result must not be cached)", hits.Load())
			}
		})
	}
}

func TestJWKSFetcherBodySize(t *testing.T) {
	t.Parallel()
	padded := func(n int) []byte {
		prefix := `{"keys":[],"pad":"`
		suffix := `"}`
		return []byte(prefix + strings.Repeat("a", n-len(prefix)-len(suffix)) + suffix)
	}
	tests := []struct {
		name    string
		body    []byte
		wantErr error
	}{
		{"at cap", padded(maxJWKSBytes), nil},
		{"one byte over cap", padded(maxJWKSBytes + 1), ErrJWKSTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, _ := jwksTestServer(t, serveBody(tc.body))
			f := devFetcher(JWTBearerConfig{})
			_, err := f.Fetch(context.Background(), srv.URL)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestJWKSFetcherTimeout(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv, _ := jwksTestServer(t, func(http.ResponseWriter, *http.Request) { <-release })
	t.Cleanup(func() { close(release) })
	f := devFetcher(JWTBearerConfig{JWKSFetchTimeout: 100 * time.Millisecond})

	start := time.Now()
	_, err := f.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("fetch took %v, timeout not enforced", elapsed)
	}
	if f.size() != 0 {
		t.Fatal("timed out fetch was cached")
	}
}

// fakeClock is a goroutine-safe settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestJWKSFetcherCacheHitThenTTLExpiry(t *testing.T) {
	t.Parallel()
	const ttl = time.Minute
	var kid atomic.Value
	kid.Store("old")
	srv, hits := jwksTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		serveBody(testJWKSDocument(t, kid.Load().(string)))(w, r)
	})
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	f := devFetcher(JWTBearerConfig{JWKSCacheTTL: ttl})
	f.now = clock.now

	steps := []struct {
		name     string
		advance  time.Duration
		rotate   bool
		wantKid  string
		wantHits int32
	}{
		{"first fetch hits network", 0, false, "old", 1},
		{"second fetch served from cache", ttl - time.Second, true, "old", 1},
		{"fetch after ttl picks up rotated key", 2 * time.Second, false, "new", 2},
	}
	// Steps are sequential by design: each depends on cache state left by
	// the previous one.
	for _, st := range steps {
		clock.advance(st.advance)
		if st.rotate {
			kid.Store("new")
		}
		keys, err := f.Fetch(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		if len(keys) != 1 || keys[0].Kid != st.wantKid {
			t.Fatalf("%s: keys = %+v, want kid %q", st.name, keys, st.wantKid)
		}
		if hits.Load() != st.wantHits {
			t.Fatalf("%s: hits = %d, want %d", st.name, hits.Load(), st.wantHits)
		}
	}
}

func TestJWKSFetcherCacheIsBounded(t *testing.T) {
	t.Parallel()
	const maxEntries = 3
	srv, _ := jwksTestServer(t, serveBody([]byte(`{"keys":[]}`)))
	f := devFetcher(JWTBearerConfig{JWKSCacheMaxEntries: maxEntries})
	for i := 0; i < 20; i++ {
		u := srv.URL + "/jwks/" + string(rune('a'+i))
		if _, err := f.Fetch(context.Background(), u); err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
		if got := f.size(); got > maxEntries {
			t.Fatalf("after %d fetches size = %d, want <= %d", i+1, got, maxEntries)
		}
	}
	if got := f.size(); got != maxEntries {
		t.Fatalf("size = %d, want %d", got, maxEntries)
	}
}

func TestJWKSFetcherDefaults(t *testing.T) {
	t.Parallel()
	f := newJWKSFetcher(nil)
	if f.ttl != DefaultJWKSCacheTTL || f.maxEntries != DefaultJWKSCacheMaxEntries || f.allowPrivate {
		t.Fatalf("unexpected defaults: ttl=%v max=%d allowPrivate=%v", f.ttl, f.maxEntries, f.allowPrivate)
	}
}

// Regression for zitadel/oidc#541 and kratos#4572: a JWKS whose keys all fail
// to parse must be an error, not a silently cached empty key set.
func TestJWKSFetcherAllKeysMalformedIsError(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
		want    int
	}{
		{"all malformed", `{"keys":[{"kty":"RSA","n":"!!","e":"AQAB","kid":"a"},{"kty":"EC","crv":"P-256","x":"!","y":"!","kid":"b"}]}`, true, 0},
		{"one good one bad", string(testJWKSDocument(t, "good")), false, 1},
		{"empty keys array", `{"keys":[]}`, false, 0},
		{"not json", `<html>`, true, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := parseJWKSBytes([]byte(tc.body))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if len(keys) != tc.want {
				t.Fatalf("got %d keys, want %d", len(keys), tc.want)
			}
		})
	}
}
