package theauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

var (
	testServerAuthMu sync.Mutex
	testServerAuth   = map[string]*theauth.TheAuth{}
)

func newTestServer(t *testing.T) (*httptest.Server, *theauth.TheAuth) {
	t.Helper()
	a, _ := newTestAuth(t)
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(func() {
		srv.Close()
		testServerAuthMu.Lock()
		delete(testServerAuth, srv.URL)
		testServerAuthMu.Unlock()
	})
	theauth.SetBaseURLForTest(a, srv.URL)
	testServerAuthMu.Lock()
	testServerAuth[srv.URL] = a
	testServerAuthMu.Unlock()
	return srv, a
}

func TestMagicLinkRequestEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	body, _ := json.Marshal(map[string]string{"email": "h@h.com"})
	resp, err := http.Post(srv.URL+"/auth/magic-link", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestMeRequiresSession(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// --- v0.2 email + password end-to-end coverage ---

// postJSON sends a request to the test server with the given body, optionally
// attaching cookies, and returns the response + decoded body.
func postJSON(t *testing.T, srv *httptest.Server, path string, body any, cookies []*http.Cookie) (*http.Response, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", srv.URL+path, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf, _ := io.ReadAll(resp.Body)
	return resp, buf
}

func TestEndToEndEmailPasswordFlow(t *testing.T) {
	srv, _ := newTestServer(t)
	email := "e2epw@h.com"
	pw := "first-password-12345"
	newPW := "second-password-67890"

	// Signup
	resp, _ := postJSON(t, srv, "/auth/email-password/signup", map[string]string{
		"email": email, "password": pw,
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("signup expected 201; got %d", resp.StatusCode)
	}
	signupCookies := resp.Cookies()
	if len(signupCookies) == 0 {
		t.Fatal("signup must set session cookie")
	}

	// /auth/me reflects the new user, EmailVerifiedAt is nil (soft verification).
	req, _ := http.NewRequest("GET", srv.URL+"/auth/me", nil)
	for _, c := range signupCookies {
		req.AddCookie(c)
	}
	meResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = meResp.Body.Close() }()
	if meResp.StatusCode != 200 {
		t.Fatalf("/me expected 200 after signup; got %d", meResp.StatusCode)
	}
	var me theauth.User
	if err := json.NewDecoder(meResp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if me.Email != email {
		t.Fatalf("got me.email=%q", me.Email)
	}
	if me.EmailVerifiedAt != nil {
		t.Fatal("EmailVerifiedAt must be nil for password signup (soft verification)")
	}

	// Signin with original password — issues a NEW session cookie.
	resp, _ = postJSON(t, srv, "/auth/email-password/signin", map[string]string{
		"email": email, "password": pw,
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("signin expected 200; got %d", resp.StatusCode)
	}
	signinCookies := resp.Cookies()
	if len(signinCookies) == 0 {
		t.Fatal("signin must set session cookie")
	}

	// Request password reset — handler always responds 200.
	resp, _ = postJSON(t, srv, "/auth/email-password/forgot", map[string]string{
		"email": email,
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("forgot expected 200; got %d", resp.StatusCode)
	}
	// Pull the actual token via the test helper (production reads it from email).
	resetToken, err := theauth.RequestPasswordResetForTest(getAuth(t, srv), context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	if resetToken == "" {
		t.Fatal("expected non-empty reset token")
	}

	// Consume reset.
	resp, _ = postJSON(t, srv, "/auth/email-password/reset", map[string]string{
		"token": resetToken, "newPassword": newPW,
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("reset expected 200; got %d", resp.StatusCode)
	}

	// Old session cookie is now revoked — /me returns 401.
	req, _ = http.NewRequest("GET", srv.URL+"/auth/me", nil)
	for _, c := range signinCookies {
		req.AddCookie(c)
	}
	meResp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = meResp2.Body.Close()
	if meResp2.StatusCode != 401 {
		t.Fatalf("expected old session to be revoked (401); got %d", meResp2.StatusCode)
	}

	// Old password rejected with invalid_credentials.
	resp, body := postJSON(t, srv, "/auth/email-password/signin", map[string]string{
		"email": email, "password": pw,
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old-pw signin expected 401; got %d body=%s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(theauth.CodeInvalidCredentials)) {
		t.Fatalf("expected invalid_credentials code; body=%s", body)
	}

	// New password works.
	resp, _ = postJSON(t, srv, "/auth/email-password/signin", map[string]string{
		"email": email, "password": newPW,
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("new-pw signin expected 200; got %d", resp.StatusCode)
	}
}

func TestSignupWeakPasswordReturns400(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, body := postJSON(t, srv, "/auth/email-password/signup", map[string]string{
		"email": "weak@h.com", "password": "tooshort111", // 11 chars
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400; got %d body=%s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(theauth.CodeWeakPassword)) {
		t.Fatalf("expected weak_password code in body; got %s", body)
	}
}

func TestSignupEmailTakenReturns409(t *testing.T) {
	srv, _ := newTestServer(t)
	for i := 0; i < 2; i++ {
		resp, body := postJSON(t, srv, "/auth/email-password/signup", map[string]string{
			"email": "dup@h.com", "password": "valid-password-1234",
		}, nil)
		if i == 0 && resp.StatusCode != http.StatusCreated {
			t.Fatalf("first signup expected 201; got %d", resp.StatusCode)
		}
		if i == 1 {
			if resp.StatusCode != http.StatusConflict {
				t.Fatalf("dup signup expected 409; got %d body=%s", resp.StatusCode, body)
			}
			if !bytes.Contains(body, []byte(theauth.CodeEmailTaken)) {
				t.Fatalf("expected email_taken code; body=%s", body)
			}
		}
	}
}

func TestSigninRateLimited(t *testing.T) {
	// Fresh auth with low per-IP limit so we can assert the 429 boundary.
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		SessionTTL:        time.Hour,
		MagicLinkTTL:      15 * time.Minute,
		RateLimitPerIP:    5,
		RateLimitPerEmail: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	// 6 signin attempts from same IP within a minute — 6th should 429.
	// All attempts use a fresh email per request so the per-email limiter (100/min)
	// doesn't kick in first. The per-IP limiter (5/min) is what we're testing.
	for i := 0; i < 5; i++ {
		resp, _ := postJSON(t, srv, "/auth/email-password/signin", map[string]string{
			"email":    fmt.Sprintf("nobody%d@h.com", i),
			"password": "whatever-12345",
		}, nil)
		// Expect 401 (invalid_credentials) on each — the request was allowed
		// through the rate limiter, just rejected by the service.
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401; got %d", i+1, resp.StatusCode)
		}
	}
	resp, body := postJSON(t, srv, "/auth/email-password/signin", map[string]string{
		"email": "yetanother@h.com", "password": "whatever-12345",
	}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("6th attempt expected 429; got %d body=%s", resp.StatusCode, body)
	}
}

// Tests the per-email limit boundary independently of per-IP. Uses a fresh
// auth instance with per-email=3 so the 4th attempt 429s.
func TestSigninRateLimitedPerEmail(t *testing.T) {
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		SessionTTL:        time.Hour,
		MagicLinkTTL:      15 * time.Minute,
		RateLimitPerIP:    100,
		RateLimitPerEmail: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	email := "perlimit@h.com"
	for i := 0; i < 3; i++ {
		resp, _ := postJSON(t, srv, "/auth/email-password/signin", map[string]string{
			"email": email, "password": "wrong-password-12345",
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401; got %d", i+1, resp.StatusCode)
		}
	}
	resp, _ := postJSON(t, srv, "/auth/email-password/signin", map[string]string{
		"email": email, "password": "wrong-password-12345",
	}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("4th attempt on same email expected 429; got %d", resp.StatusCode)
	}
}

// getAuth fishes the *TheAuth back out of the server context. newTestServer
// stores it on a package-level for reuse here.
func getAuth(t *testing.T, srv *httptest.Server) *theauth.TheAuth {
	t.Helper()
	testServerAuthMu.Lock()
	defer testServerAuthMu.Unlock()
	a, ok := testServerAuth[srv.URL]
	if !ok {
		t.Fatal("no test auth registered for server URL")
	}
	return a
}

func TestEndToEndMagicLinkFlow(t *testing.T) {
	srv, a := newTestServer(t)
	ctx := context.Background()
	token, err := theauth.RequestMagicLinkForTest(a, ctx, "e2e@h.com")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(srv.URL + "/auth/magic-link/verify?token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}
	req, _ := http.NewRequest("GET", srv.URL+"/auth/me", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	meResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = meResp.Body.Close() }()
	if meResp.StatusCode != 200 {
		t.Fatalf("expected 200 on /me, got %d", meResp.StatusCode)
	}
	var me theauth.User
	if err := json.NewDecoder(meResp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if me.Email != "e2e@h.com" {
		t.Fatalf("got email %q", me.Email)
	}
}
