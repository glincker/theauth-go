package as_test

import (
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

// newLimitedAS builds an AS with the supplied limits and (optionally) a
// trusted proxy list, and returns a request helper that posts forms.
func newLimitedAS(t *testing.T, limits *theauth.ASRateLimits, proxies []netip.Prefix) (*httptest.Server, *theauth.TheAuth) {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	a, err := theauth.New(theauth.Config{
		Storage:        memory.New(),
		BaseURL:        "https://auth.example.com",
		EncryptionKey:  key,
		TrustedProxies: proxies,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			Resources:       []theauth.ProtectedResource{{Identifier: "https://files.example.com/mcp", Scopes: []string{"files.read"}}},
			DisableRotation: true,
			RateLimits:      limits,
		},
		SuppressTrustedProxiesWarning: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, a
}

func postRaw(t *testing.T, srv *httptest.Server, path string, form url.Values, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}

func TestASEndpointRateLimits(t *testing.T) {
	endpoints := []string{"/oauth/token", "/oauth/revoke", "/oauth/introspect"}
	for _, ep := range endpoints {
		t.Run("per-IP limit on "+ep, func(t *testing.T) {
			srv, _ := newLimitedAS(t, &theauth.ASRateLimits{PerIPPerMinute: 3, PerClientPerMinute: -1}, nil)
			var codes []int
			for i := 0; i < 5; i++ {
				resp := postRaw(t, srv, ep, url.Values{"client_id": {"x"}, "token": {"t"}, "grant_type": {"client_credentials"}}, nil)
				codes = append(codes, resp.StatusCode)
				if resp.StatusCode == http.StatusTooManyRequests && resp.Header.Get("Retry-After") == "" {
					t.Fatal("429 without Retry-After")
				}
			}
			if codes[2] == http.StatusTooManyRequests || codes[3] != http.StatusTooManyRequests || codes[4] != http.StatusTooManyRequests {
				t.Fatalf("status sequence %v: want the 4th request onward limited", codes)
			}
		})
	}

	t.Run("per-client limit counts only secret-bearing requests", func(t *testing.T) {
		srv, _ := newLimitedAS(t, &theauth.ASRateLimits{PerIPPerMinute: -1, PerClientPerMinute: 2}, nil)
		guess := func(secret string) int {
			form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"victim"}}
			if secret != "" {
				form.Set("client_secret", secret)
			}
			return postRaw(t, srv, "/oauth/token", form, nil).StatusCode
		}
		for i := 0; i < 6; i++ {
			if guess("") == http.StatusTooManyRequests {
				t.Fatal("secretless requests must not consume the client budget")
			}
		}
		got := []int{guess("a"), guess("b"), guess("c")}
		if got[0] == 429 || got[1] == 429 || got[2] != 429 {
			t.Fatalf("secret guesses: %v, want third limited", got)
		}
	})

	t.Run("limits can be turned off", func(t *testing.T) {
		srv, _ := newLimitedAS(t, &theauth.ASRateLimits{PerIPPerMinute: -1, PerClientPerMinute: -1}, nil)
		for i := 0; i < 20; i++ {
			if postRaw(t, srv, "/oauth/token", url.Values{"client_id": {"x"}, "client_secret": {"y"}}, nil).StatusCode == 429 {
				t.Fatal("limited although disabled")
			}
		}
	})
}

func TestASRateLimitHonorsTrustedProxiesFromTheRight(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	srv, _ := newLimitedAS(t, &theauth.ASRateLimits{PerIPPerMinute: 2, PerClientPerMinute: -1}, proxies)
	send := func(xff string) int {
		return postRaw(t, srv, "/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"x"}},
			map[string]string{"X-Forwarded-For": xff}).StatusCode
	}
	// Two real clients behind the proxy get separate budgets.
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if send(ip) == 429 || send(ip) == 429 {
			t.Fatalf("%s should have its own budget", ip)
		}
	}
	// A client rotating a forged leftmost entry stays in one bucket, because
	// the proxy appended the real address on the right.
	var limited bool
	for i := 0; i < 5; i++ {
		spoof := "10.9." + string(rune('0'+i)) + ".1, 203.0.113.9"
		if send(spoof) == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Fatal("rotating the leftmost X-Forwarded-For entry bypassed the per-IP limit")
	}
}

func TestSharedLimiterAcrossReplicas(t *testing.T) {
	// Two AS instances sharing one limiter back the same per-IP budget.
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	shared := newSharedStores()
	build := func() *httptest.Server {
		a, err := theauth.New(theauth.Config{
			Storage: memory.New(), BaseURL: "https://auth.example.com", EncryptionKey: key,
			Stores: shared, SuppressTrustedProxiesWarning: true,
			AuthorizationServer: &theauth.AuthorizationServerConfig{
				Issuer: "https://auth.example.com", DisableRotation: true,
				Resources:  []theauth.ProtectedResource{{Identifier: "https://files.example.com/mcp"}},
				RateLimits: &theauth.ASRateLimits{PerIPPerMinute: 2, PerClientPerMinute: -1},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(a.Close)
		r := chi.NewRouter()
		a.Mount(r)
		srv := httptest.NewServer(r)
		t.Cleanup(srv.Close)
		return srv
	}
	a, b := build(), build()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"x"}}
	if postRaw(t, a, "/oauth/token", form, nil).StatusCode == 429 || postRaw(t, b, "/oauth/token", form, nil).StatusCode == 429 {
		t.Fatal("first two requests should pass")
	}
	if postRaw(t, b, "/oauth/token", form, nil).StatusCode != 429 {
		t.Fatal("third request across replicas should hit the shared budget")
	}
}
