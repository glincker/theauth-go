// Package oauthtest provides shared httptest scaffolding for the OAuth
// provider packages under provider/. It lives under internal/ so external
// consumers cannot import it (Go's standard internal-package rule); it
// exists purely to dedupe the boilerplate that would otherwise repeat
// across each provider's _test.go file.
package oauthtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TokenExpect is the expected form values on a token exchange request.
// Empty strings mean "do not assert this field"; only non-empty fields
// are compared, which keeps callers free to assert only the values they
// care about for a given test.
type TokenExpect struct {
	ClientID     string
	ClientSecret string
	Code         string
	CodeVerifier string
	RedirectURI  string
	GrantType    string // typically "authorization_code"
}

// AssertTokenForm verifies a token endpoint request body. Call from the
// mock handler after parsing the form. Fails the test on the first
// mismatch with a clear message identifying the offending field. Accepts
// testing.TB so tests can pass a fake TB for self-verification.
func AssertTokenForm(t testing.TB, r *http.Request, want TokenExpect) {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Fatalf("oauthtest: ParseForm: %v", err)
	}
	check := func(field, expected string) {
		t.Helper()
		if expected == "" {
			return
		}
		if got := r.FormValue(field); got != expected {
			t.Errorf("oauthtest: form %q = %q, want %q", field, got, expected)
		}
	}
	check("client_id", want.ClientID)
	check("client_secret", want.ClientSecret)
	check("code", want.Code)
	check("code_verifier", want.CodeVerifier)
	check("redirect_uri", want.RedirectURI)
	check("grant_type", want.GrantType)
}

// AssertBearer verifies the Authorization header equals "Bearer " + token.
// Fails the test (non-fatal) on mismatch so the caller can still drive a
// full response and surface multiple issues per run.
func AssertBearer(t testing.TB, r *http.Request, token string) {
	t.Helper()
	want := "Bearer " + token
	if got := r.Header.Get("Authorization"); got != want {
		t.Errorf("oauthtest: Authorization = %q, want %q", got, want)
	}
}

// WriteJSON writes a JSON body with Content-Type: application/json. Logs
// (does not fail) on encode errors since the test will already fail on
// the missing body shape.
func WriteJSON(t testing.TB, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Errorf("oauthtest: WriteJSON encode: %v", err)
	}
}

// NewMux returns a fresh http.ServeMux paired with an httptest.Server that
// serves it. The server is automatically closed via t.Cleanup so callers
// never need to remember to defer srv.Close().
func NewMux(t testing.TB) (*http.ServeMux, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return mux, srv
}
