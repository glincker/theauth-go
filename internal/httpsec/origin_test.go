package httpsec

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOriginAllowed(t *testing.T) {
	const base = "https://app.example.com"
	trusted := []string{"https://admin.example.com"}
	tests := []struct {
		name    string
		method  string
		headers map[string]string
		want    bool
	}{
		{"safe method skips check", http.MethodGet, map[string]string{"Cookie": "s=1", "Origin": "https://evil.test"}, true},
		{"bearer skips check", http.MethodPost, map[string]string{"Authorization": "Bearer abc", "Cookie": "s=1", "Origin": "https://evil.test"}, true},
		{"no cookie skips check", http.MethodPost, map[string]string{"Origin": "https://evil.test"}, true},
		{"same origin", http.MethodPost, map[string]string{"Cookie": "s=1", "Origin": "https://APP.example.com"}, true},
		{"trusted origin", http.MethodPost, map[string]string{"Cookie": "s=1", "Origin": "https://admin.example.com"}, true},
		{"cross origin", http.MethodPost, map[string]string{"Cookie": "s=1", "Origin": "https://evil.test"}, false},
		{"sibling subdomain", http.MethodPost, map[string]string{"Cookie": "s=1", "Origin": "https://x.example.com"}, false},
		{"scheme downgrade", http.MethodDelete, map[string]string{"Cookie": "s=1", "Origin": "http://app.example.com"}, false},
		{"opaque null origin", http.MethodPost, map[string]string{"Cookie": "s=1", "Origin": "null"}, false},
		{"referer same origin", http.MethodPost, map[string]string{"Cookie": "s=1", "Referer": "https://app.example.com/page?x=1"}, true},
		{"referer cross origin", http.MethodPost, map[string]string{"Cookie": "s=1", "Referer": "https://evil.test/p"}, false},
		{"fetch metadata cross-site", http.MethodPost, map[string]string{"Cookie": "s=1", "Sec-Fetch-Site": "cross-site"}, false},
		{"fetch metadata same-site", http.MethodPost, map[string]string{"Cookie": "s=1", "Sec-Fetch-Site": "same-site"}, false},
		{"fetch metadata same-origin", http.MethodPost, map[string]string{"Cookie": "s=1", "Sec-Fetch-Site": "same-origin"}, true},
		{"no signals at all", http.MethodPost, map[string]string{"Cookie": "s=1"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/x", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := OriginAllowed(r, base, trusted); got != tc.want {
				t.Fatalf("OriginAllowed = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNormalizeOrigins(t *testing.T) {
	got, err := NormalizeOrigins([]string{"HTTPS://Admin.Example.com/path", " http://localhost:3000 "})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "https://admin.example.com" || got[1] != "http://localhost:3000" {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{"example.com", "/relative", ""} {
		t.Run("rejects "+bad, func(t *testing.T) {
			_, err := NormalizeOrigins([]string{bad})
			if err == nil || !strings.Contains(err.Error(), "TrustedOrigins") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestCookieWriterAddsSecure(t *testing.T) {
	tests := []struct {
		name   string
		cookie string
		want   string
	}{
		{"adds Secure", "sid=1; Path=/; HttpOnly", "sid=1; Path=/; HttpOnly; Secure"},
		{"keeps existing Secure once", "sid=1; Path=/; secure", "sid=1; Path=/; secure"},
		{"name containing secure is not enough", "secure=1; Path=/", "secure=1; Path=/; Secure"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			w := NewCookieWriter(rec)
			w.Header().Add("Set-Cookie", tc.cookie)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			got := rec.Result().Header.Values("Set-Cookie")
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("Set-Cookie = %v, want %q", got, tc.want)
			}
		})
	}
	rec := httptest.NewRecorder()
	w := NewCookieWriter(rec)
	w.Header().Add("Set-Cookie", "a=1")
	w.Flush()
	if got := rec.Header().Get("Set-Cookie"); got != "a=1; Secure" {
		t.Fatalf("Flush must upgrade cookies, got %q", got)
	}
	if w.Unwrap() != http.ResponseWriter(rec) {
		t.Fatal("Unwrap must return the inner writer")
	}
}

func TestCookiePolicyWithSecureNeverDowngrades(t *testing.T) {
	if !(CookiePolicy{}).WithSecure(true).Secure {
		t.Fatal("WithSecure(true) must enable Secure")
	}
	if !(CookiePolicy{Secure: true}).WithSecure(false).Secure {
		t.Fatal("WithSecure(false) must not clear Secure")
	}
}
