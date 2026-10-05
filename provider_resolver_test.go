package theauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	ghprov "github.com/glincker/theauth-go/v2/provider/github"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

type mapResolver struct {
	mu  sync.Mutex
	m   map[string]theauth.Provider
	err error
}

func (r *mapResolver) Resolve(_ context.Context, name string) (theauth.Provider, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, false, r.err
	}
	p, ok := r.m[name]
	return p, ok, nil
}

func (r *mapResolver) List(context.Context) ([]theauth.Provider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]theauth.Provider, 0, len(r.m))
	for _, p := range r.m {
		out = append(out, p)
	}
	return out, nil
}

func (r *mapResolver) mutate(f func(m map[string]theauth.Provider)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(r.m)
}

func newResolverServer(t *testing.T, res theauth.ProviderResolver, first bool, ttl time.Duration, static ...theauth.Provider) (*httptest.Server, *theauth.TheAuth) {
	t.Helper()
	a, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", EncryptionKey: make([]byte, 32),
		Providers: static, ProviderResolver: res, ProviderResolverFirst: first, ProviderResolverTTL: ttl,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return srv, a
}

func startStatus(t *testing.T, srv *httptest.Server, name string) (int, string) {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(srv.URL + "/auth/providers/" + name + "/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

func ghFor(authorize string) theauth.Provider {
	return ghprov.New(ghprov.Config{ClientID: "cid", ClientSecret: "sec", AuthorizeURL: authorize})
}

func TestProviderResolverRuntimeLifecycle(t *testing.T) {
	res := &mapResolver{m: map[string]theauth.Provider{}}
	srv, a := newResolverServer(t, res, false, time.Minute)

	if code, _ := startStatus(t, srv, "github"); code != http.StatusNotFound {
		t.Fatalf("before add: %d", code)
	}
	res.mutate(func(m map[string]theauth.Provider) { m["github"] = ghFor("https://idp-one.test/authorize") })
	a.InvalidateProvider("github")
	code, loc := startStatus(t, srv, "github")
	if code != http.StatusFound || loc == "" || loc[:len("https://idp-one.test/authorize")] != "https://idp-one.test/authorize" {
		t.Fatalf("after add: %d %q", code, loc)
	}

	res.mutate(func(m map[string]theauth.Provider) { m["github"] = ghFor("https://idp-two.test/authorize") })
	if _, loc := startStatus(t, srv, "github"); loc[:len("https://idp-one.test")] != "https://idp-one.test" {
		t.Fatalf("edit must wait for invalidation or TTL: %q", loc)
	}
	a.InvalidateProvider("github")
	if _, loc := startStatus(t, srv, "github"); loc[:len("https://idp-two.test")] != "https://idp-two.test" {
		t.Fatalf("edit after invalidation: %q", loc)
	}

	res.mutate(func(m map[string]theauth.Provider) { delete(m, "github") })
	a.InvalidateProvider("github")
	if code, _ := startStatus(t, srv, "github"); code != http.StatusNotFound {
		t.Fatalf("after removal: %d", code)
	}

	res.mutate(func(m map[string]theauth.Provider) { m["github"] = ghFor("https://idp-one.test/authorize") })
	a.InvalidateProvider("github")
	list, err := a.ListProviders(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
}

func TestProviderResolverPrecedence(t *testing.T) {
	tests := []struct {
		name  string
		first bool
		want  string
	}{
		{"static wins by default", false, "https://static.test"},
		{"resolver first", true, "https://dynamic.test"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := &mapResolver{m: map[string]theauth.Provider{"github": ghFor("https://dynamic.test/authorize")}}
			srv, _ := newResolverServer(t, res, tc.first, 0, ghFor("https://static.test/authorize"))
			_, loc := startStatus(t, srv, "github")
			if len(loc) < len(tc.want) || loc[:len(tc.want)] != tc.want {
				t.Fatalf("location %q, want prefix %q", loc, tc.want)
			}
		})
	}
}

func TestProviderResolverFailsClosed(t *testing.T) {
	res := &mapResolver{m: map[string]theauth.Provider{}, err: errors.New("backend down")}
	srv, _ := newResolverServer(t, res, false, 0, ghFor("https://static.test/authorize"))
	if code, _ := startStatus(t, srv, "corp"); code != http.StatusServiceUnavailable {
		t.Fatalf("resolver error: %d", code)
	}
	if code, loc := startStatus(t, srv, "github"); code != http.StatusFound || loc == "" {
		t.Fatalf("static provider must keep working: %d", code)
	}
	if code, _ := startStatus(t, srv, "Bad%20Name"); code != http.StatusNotFound {
		t.Fatalf("invalid name must 404 without reaching the resolver: %d", code)
	}
}

func TestProviderResolverRequiresEncryptionKey(t *testing.T) {
	_, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost",
		ProviderResolver: &mapResolver{m: map[string]theauth.Provider{}},
	})
	if err == nil {
		t.Fatal("expected error without EncryptionKey")
	}
}
