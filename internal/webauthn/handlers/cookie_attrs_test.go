package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// wantCookie pins the attributes every cookie writer in this package must emit.
type wantCookie struct {
	name  string
	path  string
	clear bool
}

func checkCookieAttrs(t *testing.T, rec *httptest.ResponseRecorder, want wantCookie) {
	t.Helper()
	var got *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == want.name {
			got = c
		}
	}
	if got == nil {
		t.Fatalf("cookie %q not written", want.name)
	}
	if !got.Secure || !got.HttpOnly {
		t.Errorf("Secure=%v HttpOnly=%v, want both true", got.Secure, got.HttpOnly)
	}
	if got.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite=%v, want Lax", got.SameSite)
	}
	if got.Path != want.path {
		t.Errorf("Path=%q, want %q", got.Path, want.path)
	}
	if got.Domain != "" || got.Partitioned {
		t.Errorf("Domain=%q Partitioned=%v, want host-only and unpartitioned by default", got.Domain, got.Partitioned)
	}
	if want.clear && got.MaxAge >= 0 {
		t.Errorf("MaxAge=%d, want negative for a cleared cookie", got.MaxAge)
	}
	if !want.clear && got.Value == "" {
		t.Error("cookie value is empty")
	}
}

func TestCookieAttrsPinned(t *testing.T) {
	h := New(nil, SessionCookieConfig{Name: "sid", SecureFlag: true, TTL: time.Hour},
		ChallengeCookieConfig{Path: "/auth/webauthn", SecureFlag: true, TTL: time.Minute}, nil)
	tests := []struct {
		name  string
		write func(w http.ResponseWriter)
		want  wantCookie
	}{
		{"session", func(w http.ResponseWriter) { h.setSessionCookie(w, "tok") }, wantCookie{name: "sid", path: "/"}},
		{"challenge set", func(w http.ResponseWriter) { h.setChallengeCookie(w, "chal") }, wantCookie{name: webauthnChallengeCookieName, path: "/auth/webauthn"}},
		{"challenge clear", func(w http.ResponseWriter) { h.clearChallengeCookie(w) }, wantCookie{name: webauthnChallengeCookieName, path: "/auth/webauthn", clear: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.write(rec)
			checkCookieAttrs(t, rec, tc.want)
		})
	}
}
