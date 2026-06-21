package bench

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// BenchmarkSessionLookup measures the per-request cost of validating a
// session cookie through the Authn middleware path. Runs against the
// in-memory adapter so the number is the floor (real Postgres adds a
// round trip).
func BenchmarkSessionLookup(b *testing.B) {
	a, h := newBenchRouter(b)

	signupReq := httptest.NewRequest(http.MethodPost, "/auth/email-password/signup",
		bytes.NewReader([]byte(`{"email":"lookup@example.com","password":"correct-horse-battery-staple"}`)))
	signupReq.Header.Set("Content-Type", "application/json")
	signupRec := httptest.NewRecorder()
	h.ServeHTTP(signupRec, signupReq)

	// Extract the session cookie from the signup response.
	var cookie *http.Cookie
	for _, c := range signupRec.Result().Cookies() {
		if c.Name == "theauth_session" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		b.Fatalf("no session cookie from signup")
	}

	meReq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	meReq.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, meReq)
	if rec.Code != http.StatusOK {
		b.Fatalf("/auth/me status %d", rec.Code)
	}
	_ = a

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("/auth/me status %d body %s", rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
}
