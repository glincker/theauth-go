package spiffe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// bundleServer serves the given bodies in order (the last repeats) over TLS.
func bundleServer(t *testing.T, bodies ...string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(calls.Add(1)) - 1
		if i >= len(bodies) {
			i = len(bodies) - 1
		}
		if strings.HasPrefix(bodies[i], "status:") {
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write([]byte(bodies[i]))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func bundleWith(t *testing.T, v vectorFile, extra string) string {
	t.Helper()
	// Same CA as the vectors, plus bundle level members given by extra, for example `"spiffe_sequence": 9`.
	s := string(v.Bundle)
	s = strings.Replace(s, `"spiffe_sequence": 3,`, "", 1)
	s = strings.Replace(s, `"spiffe_refresh_hint": 300`, `"spiffe_refresh_hint": 60`, 1)
	if extra != "" {
		s = strings.Replace(s, "{", "{"+extra+",", 1)
	}
	return s
}

func TestStoreConfigErrors(t *testing.T) {
	cases := map[string]map[string]TrustDomainConfig{
		"bad name":     {"Bad Name": {Roots: [][]byte{[]byte("x")}}},
		"empty config": {"example.org": {}},
		"http":         {"example.org": {Endpoint: &Endpoint{URL: "http://spire.example/b"}}},
		"twice":        {"example.org": {Endpoint: &Endpoint{URL: "https://a"}}, "spiffe://example.org": {Endpoint: &Endpoint{URL: "https://b"}}},
		"bad roots":    {"example.org": {Roots: [][]byte{[]byte("not pem")}}},
	}
	for name, cfg := range cases {
		if _, err := NewStore(cfg, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStoreRotationAndLimits(t *testing.T) {
	v, _ := loadVectors(t)
	clk := &clock{t: time.Unix(1_000_000, 0)}
	first := bundleWith(t, v, `"spiffe_sequence": 5`)
	srv, calls := bundleServer(t, first, `{"keys": [], "spiffe_sequence": 6}`)
	store, err := NewStore(map[string]TrustDomainConfig{"example.org": {Endpoint: &Endpoint{URL: srv.URL, Client: srv.Client()}}}, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	b := store.Get(ctx, "example.org")
	if b == nil || len(b.X509Authorities) != 1 || b.Sequence != 5 {
		t.Fatalf("first load: %+v", b)
	}
	clk.t = clk.t.Add(59 * time.Second)
	store.Get(ctx, "example.org")
	if calls.Load() != 1 {
		t.Fatalf("polled before the hint, %d calls", calls.Load())
	}
	clk.t = clk.t.Add(2 * time.Second)
	b = store.Get(ctx, "example.org")
	if calls.Load() != 2 || b == nil || len(b.X509Authorities) != 0 || b.Sequence != 6 {
		t.Fatalf("rotation: calls=%d bundle=%+v (an empty keys array revokes every authority)", calls.Load(), b)
	}
}

func TestStoreRollbackStaleAndFailures(t *testing.T) {
	v, _ := loadVectors(t)
	clk := &clock{t: time.Unix(1_000_000, 0)}
	srv, _ := bundleServer(t, bundleWith(t, v, `"spiffe_sequence": 5`), bundleWith(t, v, `"spiffe_sequence": 4`), bundleWith(t, v, ""), "status:500")
	store, err := NewStore(map[string]TrustDomainConfig{"example.org": {Endpoint: &Endpoint{URL: srv.URL, Client: srv.Client(), MaxStale: time.Hour}}}, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if store.Get(ctx, "example.org") == nil {
		t.Fatal("first load failed")
	}
	if err := store.Refresh(ctx, "example.org"); err == nil || !strings.Contains(err.Error(), "backwards") {
		t.Fatalf("lower sequence accepted: %v", err)
	}
	if err := store.Refresh(ctx, "example.org"); err == nil {
		t.Fatal("a missing sequence replaced a sequenced bundle")
	}
	if store.Refresh(ctx, "example.org") == nil {
		t.Fatal("500 accepted")
	}
	if b := store.Get(ctx, "example.org"); b == nil || b.Sequence != 5 {
		t.Fatal("the last good bundle was lost")
	}
	clk.t = clk.t.Add(2 * time.Hour)
	if store.Get(ctx, "example.org") != nil {
		t.Fatal("a stale bundle is still trusted")
	}
}

func TestStoreFailsClosedOnFirstFetchAndOversizeBody(t *testing.T) {
	v, _ := loadVectors(t)
	srv, _ := bundleServer(t, "{not json")
	store, _ := NewStore(map[string]TrustDomainConfig{"example.org": {Endpoint: &Endpoint{URL: srv.URL, Client: srv.Client()}}}, nil)
	if store.Get(context.Background(), "example.org") != nil {
		t.Fatal("bad JSON accepted")
	}
	big, _ := bundleServer(t, bundleWith(t, v, ""))
	store, _ = NewStore(map[string]TrustDomainConfig{"example.org": {Endpoint: &Endpoint{URL: big.URL, Client: big.Client(), MaxBytes: 50}}}, nil)
	if store.Get(context.Background(), "example.org") != nil {
		t.Fatal("oversize body accepted")
	}
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.invalid/", http.StatusFound)
	}))
	defer redirect.Close()
	store, _ = NewStore(map[string]TrustDomainConfig{"example.org": {Endpoint: &Endpoint{URL: redirect.URL}}}, nil)
	if store.Get(context.Background(), "example.org") != nil {
		t.Fatal("redirect followed")
	}
}

func TestParseBundleSkipsUnusableEntries(t *testing.T) {
	v, _ := loadVectors(t)
	// The vector bundle has one CA and four jwt keys, all usable.
	b, skipped, err := ParseBundle("example.org", v.Bundle)
	if err != nil || skipped != 0 || len(b.JWTAuthorities) != 4 || len(b.X509Authorities) != 1 {
		t.Fatalf("%v %d %+v", err, skipped, b)
	}
	for name, doc := range map[string]string{
		"no keys member":   `{"spiffe_sequence": 1}`,
		"negative seq":     `{"keys": [], "spiffe_sequence": -1}`,
		"only unusable":    `{"keys": [{"kty": "EC", "use": "x509-svid", "x5c": ["AAAA"]}]}`,
		"unsupported kty":  `{"keys": [{"kty":"oct","use":"jwt-svid","kid":"a"}]}`,
		"keys of wrong ty": `{"keys": "no"}`,
	} {
		if _, _, err := ParseBundle("example.org", []byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := ParseBundle("example.org", []byte(`{"keys": []}`)); err != nil {
		t.Errorf("empty keys must be valid: %v", err)
	}
}
