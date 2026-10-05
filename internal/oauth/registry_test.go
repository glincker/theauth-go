package oauth_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/internal/oauth"
)

type fakeProvider struct{ name, tag string }

func (f fakeProvider) Name() string { return f.name }
func (f fakeProvider) AuthURL(state, _, redirectURI string, _ []string) string {
	return "https://idp.test/authorize?state=" + state + "&redirect_uri=" + redirectURI + "&tag=" + f.tag
}
func (f fakeProvider) ExchangeCode(context.Context, string, string, string) (*oauth.ProviderToken, error) {
	return nil, errors.New("not used")
}
func (f fakeProvider) UserInfo(context.Context, *oauth.ProviderToken) (*oauth.ProviderUser, error) {
	return nil, errors.New("not used")
}

type fakeResolver struct {
	mu    sync.Mutex
	m     map[string]oauth.Provider
	err   error
	calls atomic.Int64
	names []string
}

func (r *fakeResolver) Resolve(_ context.Context, name string) (oauth.Provider, bool, error) {
	r.calls.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = append(r.names, name)
	if r.err != nil {
		return nil, false, r.err
	}
	p, ok := r.m[name]
	return p, ok, nil
}

func (r *fakeResolver) set(name string, p oauth.Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p == nil {
		delete(r.m, name)
		return
	}
	r.m[name] = p
}

func TestRegistryResolvesProviderUnknownAtStartup(t *testing.T) {
	res := &fakeResolver{m: map[string]oauth.Provider{"corp": fakeProvider{name: "corp"}}}
	reg := oauth.NewRegistry(map[string]oauth.Provider{}, res, false, 0)
	p, ok, err := reg.Lookup(context.Background(), "corp")
	if err != nil || !ok || p.Name() != "corp" {
		t.Fatalf("got %v %v %v", p, ok, err)
	}
	if _, ok, err := reg.Lookup(context.Background(), "nope"); ok || err != nil {
		t.Fatalf("unknown: ok=%v err=%v", ok, err)
	}
}

func TestRegistryStaticPrecedence(t *testing.T) {
	static := map[string]oauth.Provider{"github": fakeProvider{name: "github", tag: "static"}}
	tests := []struct {
		name  string
		first bool
		want  string
		calls int64
	}{
		{"static wins by default", false, "static", 0},
		{"resolver first", true, "resolver", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := &fakeResolver{m: map[string]oauth.Provider{"github": fakeProvider{name: "github", tag: "resolver"}}}
			reg := oauth.NewRegistry(static, res, tc.first, 0)
			p, ok, err := reg.Lookup(context.Background(), "github")
			if err != nil || !ok {
				t.Fatalf("lookup: %v %v", ok, err)
			}
			if got := p.(fakeProvider).tag; got != tc.want {
				t.Fatalf("tag = %q, want %q", got, tc.want)
			}
			if res.calls.Load() != tc.calls {
				t.Fatalf("resolver calls = %d, want %d", res.calls.Load(), tc.calls)
			}
		})
	}
}

func TestRegistryResolverFirstFallsBackToStatic(t *testing.T) {
	static := map[string]oauth.Provider{"github": fakeProvider{name: "github"}}
	reg := oauth.NewRegistry(static, &fakeResolver{m: map[string]oauth.Provider{}}, true, 0)
	if _, ok, err := reg.Lookup(context.Background(), "github"); !ok || err != nil {
		t.Fatalf("fallback: %v %v", ok, err)
	}
}

func TestRegistryInvalidationAndTTL(t *testing.T) {
	res := &fakeResolver{m: map[string]oauth.Provider{"corp": fakeProvider{name: "corp"}}}
	reg := oauth.NewRegistry(nil, res, false, time.Minute)
	ctx := context.Background()
	if _, ok, _ := reg.Lookup(ctx, "corp"); !ok {
		t.Fatal("expected hit")
	}
	res.set("corp", nil)
	if _, ok, _ := reg.Lookup(ctx, "corp"); !ok {
		t.Fatal("cached entry should survive removal until invalidated")
	}
	if res.calls.Load() != 1 {
		t.Fatalf("cache missed: %d calls", res.calls.Load())
	}
	reg.Invalidate("corp")
	if _, ok, _ := reg.Lookup(ctx, "corp"); ok {
		t.Fatal("removal must take effect after invalidation")
	}
}

func TestRegistryTTLExpiry(t *testing.T) {
	res := &fakeResolver{m: map[string]oauth.Provider{"corp": fakeProvider{name: "corp"}}}
	reg := oauth.NewRegistry(nil, res, false, 20*time.Millisecond)
	ctx := context.Background()
	_, _, _ = reg.Lookup(ctx, "corp")
	res.set("corp", nil)
	time.Sleep(40 * time.Millisecond)
	if _, ok, _ := reg.Lookup(ctx, "corp"); ok {
		t.Fatal("expired entry must be re-resolved")
	}
}

func TestRegistryFailsClosedOnResolverError(t *testing.T) {
	static := map[string]oauth.Provider{"github": fakeProvider{name: "github"}}
	res := &fakeResolver{m: map[string]oauth.Provider{}, err: errors.New("db down")}
	for _, first := range []bool{false, true} {
		reg := oauth.NewRegistry(static, res, first, time.Minute)
		_, ok, err := reg.Lookup(context.Background(), "corp")
		if ok || !errors.Is(err, oauth.ErrProviderUnavailable) {
			t.Fatalf("first=%v: ok=%v err=%v", first, ok, err)
		}
	}
	reg := oauth.NewRegistry(static, res, true, time.Minute)
	if _, ok, err := reg.Lookup(context.Background(), "github"); ok || err == nil {
		t.Fatalf("resolver-first must not fall back to static when the resolver errors: %v %v", ok, err)
	}
	res.err = nil
	res.set("corp", fakeProvider{name: "corp"})
	if _, ok, err := reg.Lookup(context.Background(), "corp"); !ok || err != nil {
		t.Fatalf("errors must not be cached: %v %v", ok, err)
	}
}

func TestRegistryRejectsMismatchedProviderName(t *testing.T) {
	res := &fakeResolver{m: map[string]oauth.Provider{"corp": fakeProvider{name: "other"}}}
	reg := oauth.NewRegistry(nil, res, false, 0)
	if _, ok, err := reg.Lookup(context.Background(), "corp"); ok || !errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestRegistryValidatesNameBeforeResolver(t *testing.T) {
	res := &fakeResolver{m: map[string]oauth.Provider{}}
	reg := oauth.NewRegistry(nil, res, false, 0)
	bad := []string{"", "UPPER", "a b", "../x", "a/b", "-lead", "x'; DROP", strings.Repeat("a", 64), "a\x00b", "a%2fb"}
	for _, n := range bad {
		if _, ok, err := reg.Lookup(context.Background(), n); ok || err != nil {
			t.Fatalf("%q: ok=%v err=%v", n, ok, err)
		}
	}
	if res.calls.Load() != 0 {
		t.Fatalf("resolver saw invalid names: %v", res.names)
	}
	for _, n := range []string{"a", "corp-sso", "okta_2", strings.Repeat("a", 63)} {
		if !oauth.ValidProviderName(n) {
			t.Fatalf("%q should be valid", n)
		}
	}
}

func TestRegistryConcurrentResolve(t *testing.T) {
	res := &fakeResolver{m: map[string]oauth.Provider{"corp": fakeProvider{name: "corp"}}}
	reg := oauth.NewRegistry(map[string]oauth.Provider{"s": fakeProvider{name: "s"}}, res, false, time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				switch (i + j) % 4 {
				case 0:
					reg.Invalidate("corp")
				case 1:
					res.set("corp", fakeProvider{name: "corp"})
				default:
					_, _, _ = reg.Lookup(context.Background(), "corp")
				}
			}
		}(i)
	}
	wg.Wait()
}

type listingResolver struct {
	fakeResolver
	list []oauth.Provider
}

func (l *listingResolver) List(context.Context) ([]oauth.Provider, error) { return l.list, nil }

func TestRegistryList(t *testing.T) {
	static := map[string]oauth.Provider{"b": fakeProvider{name: "b"}, "a": fakeProvider{name: "a"}}
	l := &listingResolver{list: []oauth.Provider{fakeProvider{name: "a", tag: "dup"}, fakeProvider{name: "c"}, nil}}
	got, err := oauth.NewRegistry(static, l, false, 0).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range got {
		names = append(names, p.Name())
	}
	if strings.Join(names, ",") != "a,b,c" {
		t.Fatalf("names = %v", names)
	}
	plain, _ := oauth.NewRegistry(static, &fakeResolver{m: map[string]oauth.Provider{}}, false, 0).List(context.Background())
	if len(plain) != 2 {
		t.Fatalf("plain resolver list = %d", len(plain))
	}
}
