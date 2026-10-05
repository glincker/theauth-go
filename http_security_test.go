package theauth_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func newSecurityAuth(t *testing.T, mutate func(*theauth.Config)) *theauth.TheAuth {
	t.Helper()
	cfg := theauth.Config{
		Storage:                       memory.New(),
		BaseURL:                       "https://app.example.com",
		SuppressTrustedProxiesWarning: true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := theauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func TestHandlerServesRoutes(t *testing.T) {
	a := newSecurityAuth(t, nil)
	h := a.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/me", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("direct: got %d", rec.Code)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", http.StripPrefix("/api", h))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/me", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stripped: got %d", rec.Code)
	}
}

func TestCSRFOriginCheck(t *testing.T) {
	tests := []struct {
		name   string
		cfg    func(*theauth.Config)
		method string
		hdr    map[string]string
		want   int
	}{
		{"missing origin allowed", nil, "DELETE", map[string]string{"Cookie": "theauth_session=x"}, 401},
		{"matching origin", nil, "DELETE", map[string]string{"Cookie": "theauth_session=x", "Origin": "https://app.example.com"}, 401},
		{"matching origin case", nil, "DELETE", map[string]string{"Cookie": "theauth_session=x", "Origin": "https://APP.example.com"}, 401},
		{"sibling subdomain rejected", nil, "DELETE", map[string]string{"Cookie": "theauth_session=x", "Origin": "https://evil.example.com"}, 403},
		{"scheme mismatch rejected", nil, "DELETE", map[string]string{"Cookie": "theauth_session=x", "Origin": "http://app.example.com"}, 403},
		{"null origin rejected", nil, "DELETE", map[string]string{"Cookie": "theauth_session=x", "Origin": "null"}, 403},
		{"referer mismatch rejected", nil, "DELETE", map[string]string{"Cookie": "theauth_session=x", "Referer": "https://evil.example.com/x"}, 403},
		{"referer match", nil, "DELETE", map[string]string{"Cookie": "theauth_session=x", "Referer": "https://app.example.com/page"}, 401},
		{"no origin same-site fetch rejected", nil, "DELETE", map[string]string{"Cookie": "theauth_session=x", "Sec-Fetch-Site": "same-site"}, 403},
		{"no origin same-origin fetch allowed", nil, "DELETE", map[string]string{"Cookie": "theauth_session=x", "Sec-Fetch-Site": "same-origin"}, 401},
		{"extra trusted origin", func(c *theauth.Config) { c.TrustedOrigins = []string{"https://admin.example.com"} }, "DELETE", map[string]string{"Cookie": "theauth_session=x", "Origin": "https://admin.example.com"}, 401},
		{"bearer exempt", nil, "DELETE", map[string]string{"Authorization": "Bearer tok", "Cookie": "theauth_session=x", "Origin": "https://evil.example.com"}, 401},
		{"no cookie exempt", nil, "DELETE", map[string]string{"Origin": "https://evil.example.com"}, 401},
		{"GET exempt", nil, "GET", map[string]string{"Cookie": "theauth_session=x", "Origin": "https://evil.example.com"}, 401},
		{"opt out", func(c *theauth.Config) { c.DisableCSRFProtection = true }, "DELETE", map[string]string{"Cookie": "theauth_session=x", "Origin": "https://evil.example.com"}, 401},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newSecurityAuth(t, tc.cfg).Handler()
			path := "/auth/sessions/current"
			if tc.method == "GET" {
				path = "/auth/me"
			}
			req := httptest.NewRequest(tc.method, path, nil)
			for k, v := range tc.hdr {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d want %d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestInvalidTrustedOrigin(t *testing.T) {
	_, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "https://a.example.com", TrustedOrigins: []string{"not-a-url"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSecureCookieDerivation(t *testing.T) {
	proxy := netip.MustParsePrefix("192.0.2.0/24")
	tests := []struct {
		name       string
		cfg        func(*theauth.Config)
		remote     string
		xfp        string
		tls        bool
		wantSecure bool
	}{
		{"https baseurl", nil, "203.0.113.5:1", "", false, true},
		{"http baseurl plain", func(c *theauth.Config) { c.BaseURL = "http://localhost:8080" }, "203.0.113.5:1", "", false, false},
		{"explicit flag overrides", func(c *theauth.Config) { c.BaseURL = "http://localhost:8080"; c.SecureCookie = true }, "203.0.113.5:1", "", false, true},
		{"direct tls", func(c *theauth.Config) { c.BaseURL = "http://localhost:8080" }, "203.0.113.5:1", "", true, true},
		{"xfp from trusted proxy", func(c *theauth.Config) {
			c.BaseURL = "http://localhost:8080"
			c.TrustedProxies = []netip.Prefix{proxy}
		}, "192.0.2.9:1", "https", false, true},
		{"xfp from untrusted peer ignored", func(c *theauth.Config) {
			c.BaseURL = "http://localhost:8080"
			c.TrustedProxies = []netip.Prefix{proxy}
		}, "203.0.113.5:1", "https", false, false},
		{"xfp without trusted proxies ignored", func(c *theauth.Config) { c.BaseURL = "http://localhost:8080" }, "192.0.2.9:1", "https", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newSecurityAuth(t, tc.cfg)
			token, err := theauth.RequestMagicLinkForTest(a, context.Background(), "sec@example.com")
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token="+token, nil)
			req.RemoteAddr = tc.remote
			if tc.xfp != "" {
				req.Header.Set("X-Forwarded-Proto", tc.xfp)
			}
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			rec := httptest.NewRecorder()
			a.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			cookies := rec.Result().Cookies()
			if len(cookies) == 0 {
				t.Fatal("no cookie set")
			}
			if cookies[0].Secure != tc.wantSecure {
				t.Fatalf("secure=%v want %v", cookies[0].Secure, tc.wantSecure)
			}
		})
	}
}
