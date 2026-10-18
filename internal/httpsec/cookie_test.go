package httpsec

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCookiePolicyValidate(t *testing.T) {
	tests := []struct {
		name    string
		policy  CookiePolicy
		cookie  string
		path    string
		wantErr string
	}{
		{"zero value plain", CookiePolicy{}, "sid", "/", ""},
		{"secure lax", CookiePolicy{Secure: true}, "sid", "/", ""},
		{"none needs secure", CookiePolicy{SameSite: http.SameSiteNoneMode}, "sid", "/", "SameSite=None requires Secure"},
		{"none secure ok", CookiePolicy{Secure: true, SameSite: http.SameSiteNoneMode}, "sid", "/", ""},
		{"partitioned needs secure", CookiePolicy{Partitioned: true}, "sid", "/", "Partitioned"},
		{"partitioned secure ok", CookiePolicy{Secure: true, Partitioned: true}, "sid", "/", ""},
		{"host ok", CookiePolicy{Secure: true}, "__Host-sid", "/", ""},
		{"host needs secure", CookiePolicy{}, "__Host-sid", "/", "must be Secure"},
		{"host needs root path", CookiePolicy{Secure: true}, "__Host-sid", "/auth", "Path=/"},
		{"host forbids domain", CookiePolicy{Secure: true, Domain: "example.com"}, "__Host-sid", "/", "must not set Domain"},
		{"secure prefix ok", CookiePolicy{Secure: true, Domain: "example.com"}, "__Secure-sid", "/", ""},
		{"secure prefix needs secure", CookiePolicy{}, "__Secure-sid", "/", "must be Secure"},
		{"domain with port", CookiePolicy{Domain: "example.com:8080"}, "sid", "/", "bare host"},
		{"bad samesite", CookiePolicy{SameSite: http.SameSite(99)}, "sid", "/", "SameSite must be"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate(tc.cookie, tc.path)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("error %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestCookiePolicySetAndClear(t *testing.T) {
	p := CookiePolicy{Secure: true, Domain: "example.com", SameSite: http.SameSiteStrictMode, Partitioned: true}
	rec := httptest.NewRecorder()
	p.Set(rec, "sid", "tok", "/", time.Now().Add(time.Hour))
	set := rec.Result().Cookies()[0]
	if !set.Secure || !set.HttpOnly || set.SameSite != http.SameSiteStrictMode || set.Domain != "example.com" || !set.Partitioned || set.Path != "/" {
		t.Errorf("set cookie attrs wrong: %+v", set)
	}
	if set.MaxAge < 3500 || set.MaxAge > 3600 || set.Expires.IsZero() {
		t.Errorf("Max-Age=%d Expires=%v, want about one hour and an Expires", set.MaxAge, set.Expires)
	}

	rec = httptest.NewRecorder()
	p.Clear(rec, "sid", "/")
	clr := rec.Result().Cookies()[0]
	if clr.MaxAge >= 0 || clr.Value != "" || clr.Domain != "example.com" || !clr.Partitioned || !clr.Secure || clr.Path != "/" {
		t.Errorf("clear must repeat Domain, Path, Secure and Partitioned: %+v", clr)
	}
}

func TestCookiePolicyHostPrefixClearKeepsRequiredAttrs(t *testing.T) {
	rec := httptest.NewRecorder()
	CookiePolicy{Secure: true}.Clear(rec, "__Host-sid", "/")
	raw := rec.Header().Get("Set-Cookie")
	for _, want := range []string{"Secure", "Path=/", "Max-Age=0", "HttpOnly"} {
		if !strings.Contains(raw, want) {
			t.Errorf("%q missing %q", raw, want)
		}
	}
	if strings.Contains(raw, "Domain") {
		t.Errorf("%q must not carry Domain", raw)
	}
}

func TestCookiePolicyInvalidWritesNothing(t *testing.T) {
	rec := httptest.NewRecorder()
	CookiePolicy{}.Set(rec, "__Host-sid", "tok", "/", time.Time{})
	CookiePolicy{}.Clear(rec, "__Host-sid", "/")
	if len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("an invalid policy must not write a weaker cookie")
	}
}

func TestCookiePolicyDefaultsToLax(t *testing.T) {
	c, err := CookiePolicy{}.New("sid", "v", "/", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if c.SameSite != http.SameSiteLaxMode || c.Domain != "" || c.Partitioned || !c.HttpOnly || c.MaxAge != 0 {
		t.Errorf("zero policy drifted from historic defaults: %+v", c)
	}
}

func TestParseSameSite(t *testing.T) {
	for in, want := range map[string]http.SameSite{"": http.SameSiteLaxMode, "Lax": http.SameSiteLaxMode, "strict": http.SameSiteStrictMode, " none ": http.SameSiteNoneMode} {
		got, err := ParseSameSite(in)
		if err != nil || got != want {
			t.Errorf("ParseSameSite(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseSameSite("loose"); err == nil {
		t.Error("expected an error for loose")
	}
}

func TestForCrossSiteReturn(t *testing.T) {
	if got := (CookiePolicy{SameSite: http.SameSiteStrictMode}).ForCrossSiteReturn().SameSite; got != http.SameSiteLaxMode {
		t.Errorf("Strict became %v, want Lax", got)
	}
	if got := (CookiePolicy{Secure: true, SameSite: http.SameSiteNoneMode}).ForCrossSiteReturn().SameSite; got != http.SameSiteNoneMode {
		t.Errorf("None became %v, want None", got)
	}
}

func TestApplySecurityHeaders(t *testing.T) {
	tests := []struct {
		name   string
		secure bool
		hsts   bool
	}{
		{"https sends HSTS", true, true},
		{"plain http omits HSTS", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := SecurityHeadersMiddleware(func(*http.Request) bool { return tc.secure })(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			got := rec.Header()
			if got.Get("X-Content-Type-Options") != "nosniff" || got.Get("Referrer-Policy") != "no-referrer" || got.Get("X-Frame-Options") != "DENY" {
				t.Errorf("headers missing: %v", got)
			}
			if (got.Get("Strict-Transport-Security") != "") != tc.hsts {
				t.Errorf("HSTS=%q, want present=%v", got.Get("Strict-Transport-Security"), tc.hsts)
			}
		})
	}
}

func TestNoStorePath(t *testing.T) {
	for path, want := range map[string]bool{"/auth": true, "/auth/me": true, "/authz": false, "/.well-known/jwks.json": false} {
		if got := NoStorePath(path, "/auth"); got != want {
			t.Errorf("NoStorePath(%q) = %v, want %v", path, got, want)
		}
	}
}
