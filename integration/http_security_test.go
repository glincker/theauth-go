package integration

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/integration/internal/testutil"
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
			token, err := testutil.RequestMagicLinkForTest(a, context.Background(), "sec@example.com")
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

// pinnedCookie fails the test unless the named cookie carries the attributes every session writer
// has always emitted: Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain or Partitioned.
func pinnedCookie(t *testing.T, rec *httptest.ResponseRecorder, name string, cleared bool) *http.Cookie {
	t.Helper()
	var got *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			got = c
		}
	}
	if got == nil {
		t.Fatalf("cookie %q not written", name)
	}
	if !got.Secure || !got.HttpOnly || got.SameSite != http.SameSiteLaxMode || got.Path != "/" {
		t.Errorf("attrs Secure=%v HttpOnly=%v SameSite=%v Path=%q", got.Secure, got.HttpOnly, got.SameSite, got.Path)
	}
	if got.Domain != "" || got.Partitioned {
		t.Errorf("Domain=%q Partitioned=%v, want defaults off", got.Domain, got.Partitioned)
	}
	if cleared != (got.MaxAge < 0) {
		t.Errorf("cleared=%v but MaxAge=%d", cleared, got.MaxAge)
	}
	return got
}

func TestSessionCookieAttributesPinned(t *testing.T) {
	a := newSecurityAuth(t, nil)
	h := a.Handler()
	tests := []struct {
		name string
		do   func(t *testing.T) *httptest.ResponseRecorder
		want bool
	}{
		{"signup", func(t *testing.T) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, "/auth/email-password/signup",
				strings.NewReader(`{"email":"pin1@h.com","password":"first-password-12345"}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec
		}, false},
		{"magic link verify", func(t *testing.T) *httptest.ResponseRecorder {
			tok, err := testutil.RequestMagicLinkForTest(a, context.Background(), "pin2@h.com")
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token="+tok, nil))
			return rec
		}, false},
		{"sign out clears", func(t *testing.T) *httptest.ResponseRecorder {
			tok, err := testutil.RequestMagicLinkForTest(a, context.Background(), "pin3@h.com")
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token="+tok, nil))
			req := httptest.NewRequest(http.MethodDelete, "/auth/sessions/current", nil)
			req.AddCookie(rec.Result().Cookies()[0])
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			return out
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := tc.do(t)
			if rec.Code >= 400 {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			pinnedCookie(t, rec, "theauth_session", tc.want)
		})
	}
}

func TestCookiesConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     func(*theauth.Config)
		wantErr string
	}{
		{"zero value ok", nil, ""},
		{"strict ok", func(c *theauth.Config) { c.Cookies.SameSite = "strict" }, ""},
		{"none partitioned ok", func(c *theauth.Config) { c.Cookies.SameSite = "none"; c.Cookies.Partitioned = true }, ""},
		{"host prefix ok", func(c *theauth.Config) { c.Cookies.Prefix = "host" }, ""},
		{"host prefix with domain", func(c *theauth.Config) { c.Cookies.Prefix = "host"; c.Cookies.Domain = "example.com" }, "must not set Domain"},
		{"host prefix needs secure", func(c *theauth.Config) { c.BaseURL = "http://localhost:3000"; c.Cookies.Prefix = "host" }, "must be Secure"},
		{"none needs secure", func(c *theauth.Config) { c.BaseURL = "http://localhost:3000"; c.Cookies.SameSite = "none" }, "requires Secure"},
		{"partitioned needs secure", func(c *theauth.Config) { c.BaseURL = "http://localhost:3000"; c.Cookies.Partitioned = true }, "Partitioned"},
		{"bad samesite", func(c *theauth.Config) { c.Cookies.SameSite = "loose" }, "SameSite"},
		{"bad prefix", func(c *theauth.Config) { c.Cookies.Prefix = "both" }, "Cookies.Prefix"},
		{"name with other prefix", func(c *theauth.Config) { c.CookieName = "__Secure-sid"; c.Cookies.Prefix = "host" }, "different prefix"},
		{"hand set host name with domain", func(c *theauth.Config) { c.CookieName = "__Host-sid"; c.Cookies.Domain = "example.com" }, "must not set Domain"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := theauth.Config{Storage: memory.New(), BaseURL: "https://app.example.com", SuppressTrustedProxiesWarning: true, SuppressSecureCookieWarning: true}
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			a, err := theauth.New(cfg)
			if a != nil {
				t.Cleanup(a.Close)
			}
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("error %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestCookiesConfigAppliedToSessionCookie(t *testing.T) {
	a := newSecurityAuth(t, func(c *theauth.Config) {
		c.Cookies = theauth.CookiesConfig{Domain: "example.com", SameSite: "none", Partitioned: true, Prefix: "secure"}
	})
	h := a.Handler()
	tok, err := testutil.RequestMagicLinkForTest(a, context.Background(), "cfg1@h.com")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token="+tok, nil))
	c := rec.Result().Cookies()[0]
	if c.Name != "__Secure-theauth_session" || c.Domain != "example.com" || c.SameSite != http.SameSiteNoneMode || !c.Partitioned || !c.Secure || !c.HttpOnly {
		t.Fatalf("session cookie ignores Config.Cookies: %+v", c)
	}
	req := httptest.NewRequest(http.MethodDelete, "/auth/sessions/current", nil)
	req.AddCookie(c)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	clr := out.Result().Cookies()[0]
	if clr.Name != c.Name || clr.Domain != "example.com" || !clr.Partitioned || !clr.Secure || clr.MaxAge >= 0 {
		t.Fatalf("clear must repeat the set attributes: %+v", clr)
	}
}

func TestHostPrefixClearKeepsRequiredAttributes(t *testing.T) {
	a := newSecurityAuth(t, func(c *theauth.Config) { c.Cookies.Prefix = "host" })
	h := a.Handler()
	tok, err := testutil.RequestMagicLinkForTest(a, context.Background(), "cfg2@h.com")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token="+tok, nil))
	c := rec.Result().Cookies()[0]
	req := httptest.NewRequest(http.MethodDelete, "/auth/sessions/current", nil)
	req.AddCookie(c)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	clr := out.Result().Cookies()[0]
	if clr.Name != "__Host-theauth_session" || !clr.Secure || clr.Path != "/" || clr.Domain != "" || clr.MaxAge >= 0 {
		t.Fatalf("cleared __Host- cookie lost a required attribute: %+v", clr)
	}
}

func TestAuthResponsesAreNoStore(t *testing.T) {
	a := newSecurityAuth(t, nil)
	h := a.Handler()
	tok, err := testutil.RequestMagicLinkForTest(a, context.Background(), "ns@h.com")
	if err != nil {
		t.Fatal(err)
	}
	verify := httptest.NewRecorder()
	h.ServeHTTP(verify, httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token="+tok, nil))
	sess := verify.Result().Cookies()[0]
	withSession := func(method, path, body string) *http.Request {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(sess)
		return req
	}
	tests := []struct {
		name string
		req  *http.Request
	}{
		{"me", withSession(http.MethodGet, "/auth/me", "")},
		{"me unauthorized", httptest.NewRequest(http.MethodGet, "/auth/me", nil)},
		{"sessions list", withSession(http.MethodGet, "/auth/sessions", "")},
		{"signup", httptest.NewRequest(http.MethodPost, "/auth/email-password/signup", strings.NewReader(`{"email":"ns2@h.com","password":"first-password-12345"}`))},
		{"signin", httptest.NewRequest(http.MethodPost, "/auth/email-password/signin", strings.NewReader(`{"email":"ns2@h.com","password":"nope-password-12345"}`))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tc.req)
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control=%q (status %d), want no-store", got, rec.Code)
			}
		})
	}
}

func TestSecurityHeadersOptIn(t *testing.T) {
	tests := []struct {
		name string
		on   bool
		base string
		hsts bool
	}{
		{"off by default", false, "https://app.example.com", false},
		{"on over https", true, "https://app.example.com", true},
		{"on over http omits HSTS", true, "http://localhost:3000", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newSecurityAuth(t, func(c *theauth.Config) {
				c.SecurityHeaders = tc.on
				c.BaseURL = tc.base
				c.SuppressSecureCookieWarning = true
			}).Handler()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/me", nil))
			got := rec.Header()
			if present := got.Get("X-Content-Type-Options") != ""; present != tc.on {
				t.Errorf("X-Content-Type-Options present=%v, want %v", present, tc.on)
			}
			if tc.on && (got.Get("Referrer-Policy") == "" || got.Get("X-Frame-Options") == "") {
				t.Errorf("headers missing: %v", got)
			}
			if present := got.Get("Strict-Transport-Security") != ""; present != tc.hsts {
				t.Errorf("HSTS present=%v, want %v", present, tc.hsts)
			}
		})
	}
}
