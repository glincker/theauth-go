// Package bench holds micro-benchmarks for the hot paths. It lives under internal/ so the public
// test binary stays clean. Baselines are in BASELINES.md.
package bench

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

// TestMain silences slog for the bench package so the benchmark output
// stays clean and the BASELINES table can be pasted from the raw stdout.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

const (
	benchEmail    = "bench@example.com"
	benchPassword = "correct-horse-battery-staple"
)

func newBenchRouter(b *testing.B) (*theauth.TheAuth, http.Handler) {
	b.Helper()
	a, err := theauth.New(theauth.Config{
		Storage:           memory.New(),
		BaseURL:           "http://localhost",
		SecureCookie:      false,
		RateLimitPerIP:    10_000_000,
		RateLimitPerEmail: 10_000_000,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(a.Close)
	r := chi.NewRouter()
	a.Mount(r)
	return a, r
}

func bodyJSON(s string) *bytes.Reader { return bytes.NewReader([]byte(s)) }

// BenchmarkLoginPassword measures the password sign-in path through the HTTP handler. Argon2id
// verification dominates the cost by design.
func BenchmarkLoginPassword(b *testing.B) {
	_, h := newBenchRouter(b)

	// Sign up once to seed the user with a hashed password.
	signupReq := httptest.NewRequest(http.MethodPost, "/auth/email-password/signup",
		bodyJSON(`{"email":"`+benchEmail+`","password":"`+benchPassword+`"}`))
	signupReq.Header.Set("Content-Type", "application/json")
	signupRec := httptest.NewRecorder()
	h.ServeHTTP(signupRec, signupReq)
	if signupRec.Code != http.StatusCreated {
		b.Fatalf("signup status %d body %s", signupRec.Code, signupRec.Body.String())
	}

	signinBody := []byte(`{"email":"` + benchEmail + `","password":"` + benchPassword + `"}`)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/email-password/signin", bytes.NewReader(signinBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("signin status %d body %s", rec.Code, rec.Body.String())
		}
	}
}
