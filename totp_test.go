package theauth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
)

// newTOTPTestAuth builds a TheAuth wired with the in-memory storage and a
// TOTPConfig. Returns the auth handle plus a freshly-created user so tests
// can immediately exercise the enrollment / verify flows.
func newTOTPTestAuth(t *testing.T) (*theauth.TheAuth, theauth.User) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "http://localhost",
		EncryptionKey: key,
		TOTP:          &theauth.TOTPConfig{Issuer: "TheAuth Test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	u, err := store.CreateUser(context.Background(), theauth.User{
		ID:        ulid.New(),
		Email:     "totp@h.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, u
}

// TestTOTPNewRequiresKeyAndIssuer covers the two New-time validation rules
// for TOTPConfig.
func TestTOTPNewRequiresKeyAndIssuer(t *testing.T) {
	if _, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://x",
		TOTP: &theauth.TOTPConfig{Issuer: "x"},
	}); err == nil {
		t.Fatal("TOTP without encryption key must fail")
	}
	key := make([]byte, 32)
	if _, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://x", EncryptionKey: key,
		TOTP: &theauth.TOTPConfig{},
	}); err == nil {
		t.Fatal("TOTP without issuer must fail")
	}
}

// TestTOTPEnrollHappyPath exercises begin -> validate -> finish. The
// returned recovery codes must be exactly RecoveryCodeCount (default 10).
func TestTOTPEnrollHappyPath(t *testing.T) {
	a, u := newTOTPTestAuth(t)
	ctx := context.Background()
	res, err := theauth.BeginTOTPEnrollmentForTest(a, ctx, u.ID, u.Email)
	if err != nil {
		t.Fatal(err)
	}
	if res.Secret == "" || res.OTPAuthURL == "" || res.EnrollmentID == "" {
		t.Fatalf("EnrollTOTPResult missing fields: %+v", res)
	}
	code, err := totp.GenerateCode(res.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rc, err := theauth.FinishTOTPEnrollmentForTest(a, ctx, u.ID, res.EnrollmentID, code)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	if len(rc) != 10 {
		t.Fatalf("recovery codes: got %d want 10", len(rc))
	}
	for i, c := range rc {
		if len(c) != 10 {
			t.Fatalf("recovery code %d has length %d", i, len(c))
		}
	}
}

// TestTOTPFinishWithWrongCode exercises the negative path: the secret stays
// pending in storage and a retry with the correct code still succeeds.
func TestTOTPFinishWithWrongCode(t *testing.T) {
	a, u := newTOTPTestAuth(t)
	ctx := context.Background()
	res, err := theauth.BeginTOTPEnrollmentForTest(a, ctx, u.ID, u.Email)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := theauth.FinishTOTPEnrollmentForTest(a, ctx, u.ID, res.EnrollmentID, "000000"); err == nil {
		t.Fatal("wrong code must fail")
	}
	// Real code should still work because we preserve the enrollment on a
	// validate failure.
	good, err := totp.GenerateCode(res.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := theauth.FinishTOTPEnrollmentForTest(a, ctx, u.ID, res.EnrollmentID, good); err != nil {
		t.Fatalf("retry with good code: %v", err)
	}
}

// TestTOTPFinishTwice covers idempotency: calling /finish a second time
// against an already-confirmed user returns the documented
// ErrAlreadyEnrolled.
func TestTOTPFinishTwice(t *testing.T) {
	a, u := newTOTPTestAuth(t)
	ctx := context.Background()
	res, err := theauth.BeginTOTPEnrollmentForTest(a, ctx, u.ID, u.Email)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(res.Secret, time.Now())
	if _, err := theauth.FinishTOTPEnrollmentForTest(a, ctx, u.ID, res.EnrollmentID, code); err != nil {
		t.Fatal(err)
	}
	// Begin again to get a new enrollment token, then finish should
	// observe the already-confirmed secret and refuse.
	res2, err := theauth.BeginTOTPEnrollmentForTest(a, ctx, u.ID, u.Email)
	if err != nil {
		t.Fatal(err)
	}
	code2, _ := totp.GenerateCode(res2.Secret, time.Now())
	_, err = theauth.FinishTOTPEnrollmentForTest(a, ctx, u.ID, res2.EnrollmentID, code2)
	if err == nil {
		t.Fatal("second finish should fail with already_enrolled")
	}
	var te *theauth.TheAuthError
	if !errors.As(err, &te) || te.Code != theauth.CodeAlreadyEnrolled {
		t.Fatalf("expected CodeAlreadyEnrolled; got %v", err)
	}
}

// TestTOTPVerifyHappyPath enrolls, mints a pending session, and verifies
// the code to promote the session to full.
func TestTOTPVerifyHappyPath(t *testing.T) {
	a, u := newTOTPTestAuth(t)
	ctx := context.Background()
	res, _ := theauth.BeginTOTPEnrollmentForTest(a, ctx, u.ID, u.Email)
	code, _ := totp.GenerateCode(res.Secret, time.Now())
	if _, err := theauth.FinishTOTPEnrollmentForTest(a, ctx, u.ID, res.EnrollmentID, code); err != nil {
		t.Fatal(err)
	}
	pendingTok, sess, err := theauth.IssuePending2FAForTest(a, ctx, u.ID, "ua", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if sess.AuthLevel != theauth.AuthLevelPending2FA {
		t.Fatalf("pending session AuthLevel: got %q", sess.AuthLevel)
	}
	verifyCode, _ := totp.GenerateCode(res.Secret, time.Now())
	upgraded, fullSess, err := theauth.VerifyTOTPForTest(a, ctx, pendingTok, verifyCode)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if upgraded != pendingTok {
		t.Fatalf("expected same token after promote; got different")
	}
	if fullSess.AuthLevel != theauth.AuthLevelFull {
		t.Fatalf("expected full after verify; got %q", fullSess.AuthLevel)
	}
}

// TestTOTPVerifyBruteForceRevoke validates the five-strike pending session
// kill switch. Five consecutive wrong codes revoke the session; a sixth
// attempt sees a revoked session and fails fast.
func TestTOTPVerifyBruteForceRevoke(t *testing.T) {
	a, u := newTOTPTestAuth(t)
	ctx := context.Background()
	res, _ := theauth.BeginTOTPEnrollmentForTest(a, ctx, u.ID, u.Email)
	code, _ := totp.GenerateCode(res.Secret, time.Now())
	if _, err := theauth.FinishTOTPEnrollmentForTest(a, ctx, u.ID, res.EnrollmentID, code); err != nil {
		t.Fatal(err)
	}
	pendingTok, _, err := theauth.IssuePending2FAForTest(a, ctx, u.ID, "ua", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, _, err := theauth.VerifyTOTPForTest(a, ctx, pendingTok, "000000"); err == nil {
			t.Fatalf("attempt %d should fail", i+1)
		}
	}
	// Sixth: session is revoked, validateSession returns ErrSessionExpired.
	if _, _, err := theauth.VerifyTOTPForTest(a, ctx, pendingTok, "000000"); !errors.Is(err, theauth.ErrSessionExpired) {
		t.Fatalf("sixth attempt should see revoked session; got %v", err)
	}
}

// TestRecoveryCodeConsumeHappy enrolls, mints pending, and consumes the
// first returned recovery code to promote.
func TestRecoveryCodeConsumeHappy(t *testing.T) {
	a, u := newTOTPTestAuth(t)
	ctx := context.Background()
	res, _ := theauth.BeginTOTPEnrollmentForTest(a, ctx, u.ID, u.Email)
	code, _ := totp.GenerateCode(res.Secret, time.Now())
	rcs, err := theauth.FinishTOTPEnrollmentForTest(a, ctx, u.ID, res.EnrollmentID, code)
	if err != nil {
		t.Fatal(err)
	}
	pendingTok, _, _ := theauth.IssuePending2FAForTest(a, ctx, u.ID, "ua", "ip")
	_, sess, err := theauth.ConsumeRecoveryCodeForTest(a, ctx, pendingTok, rcs[0])
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if sess.AuthLevel != theauth.AuthLevelFull {
		t.Fatalf("after recovery: AuthLevel got %q want full", sess.AuthLevel)
	}
	// Reuse must fail (and bump the counter).
	if _, _, err := theauth.ConsumeRecoveryCodeForTest(a, ctx, pendingTok, rcs[0]); err == nil {
		t.Fatal("reuse must fail")
	}
}

// ---------- HTTP handler tests (originally handlers_totp_test.go) ----------

// newTOTPServer wires a TheAuth with TOTPConfig set and returns an httptest
// server. The integration test treats the server like any consumer would:
// only HTTP in, only HTTP out, no peeking at internals.
func newTOTPServer(t *testing.T) (*httptest.Server, *theauth.TheAuth) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:           memory.New(),
		BaseURL:           "http://placeholder",
		EncryptionKey:     key,
		RateLimitPerIP:    1000,
		RateLimitPerEmail: 1000,
		TOTP:              &theauth.TOTPConfig{Issuer: "TheAuth Step Up Test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	theauth.SetBaseURLForTest(a, srv.URL)
	return srv, a
}

// postJSONWithCookies sends a JSON body and returns response + cookies.
func postJSONWithCookies(t *testing.T, srv *httptest.Server, path string, body any, cookies []*http.Cookie) (*http.Response, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, buf
}

// TestStepUpFlow walks the full v0.5 password to TOTP step-up flow end to
// end as documented in the design doc section 10.3.
func TestStepUpFlow(t *testing.T) {
	srv, _ := newTOTPServer(t)
	email := "stepup@h.com"
	pw := "twelve-chars-min-pw"

	// 1. Signup. Issues a full session by default (no TOTP enrolled yet).
	resp, _ := postJSONWithCookies(t, srv, "/auth/email-password/signup",
		map[string]string{"email": email, "password": pw}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("signup: %d", resp.StatusCode)
	}
	full := resp.Cookies()

	// 2. Begin TOTP enrollment with the full session.
	resp, body := postJSONWithCookies(t, srv, "/auth/totp/enroll/begin", struct{}{}, full)
	if resp.StatusCode != 200 {
		t.Fatalf("enroll/begin: %d body=%s", resp.StatusCode, string(body))
	}
	var enroll struct {
		Secret       string `json:"secret"`
		OTPAuthURL   string `json:"otpAuthUrl"`
		EnrollmentID string `json:"enrollmentId"`
	}
	if err := json.Unmarshal(body, &enroll); err != nil {
		t.Fatalf("enroll begin body: %v / %s", err, body)
	}
	if enroll.Secret == "" || enroll.EnrollmentID == "" {
		t.Fatalf("enroll begin: missing fields %+v", enroll)
	}

	// 3. Compute current code and POST finish.
	code, err := totp.GenerateCode(enroll.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp, body = postJSONWithCookies(t, srv, "/auth/totp/enroll/finish",
		map[string]string{"enrollmentId": enroll.EnrollmentID, "code": code}, full)
	if resp.StatusCode != 200 {
		t.Fatalf("enroll/finish: %d body=%s", resp.StatusCode, string(body))
	}
	var rcResp struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	if err := json.Unmarshal(body, &rcResp); err != nil {
		t.Fatal(err)
	}
	if len(rcResp.RecoveryCodes) != 10 {
		t.Fatalf("recovery codes: got %d want 10", len(rcResp.RecoveryCodes))
	}

	// 4. Logout the full session.
	logoutReq, _ := http.NewRequest("DELETE", srv.URL+"/auth/sessions/current", nil)
	for _, c := range full {
		logoutReq.AddCookie(c)
	}
	if r2, err := http.DefaultClient.Do(logoutReq); err == nil {
		_ = r2.Body.Close()
	}

	// 5. Sign in again. Response must declare step=totp_required and
	// the new cookie must be pending_2fa (we can verify by hitting /auth/me
	// next, which must return 401).
	resp, body = postJSONWithCookies(t, srv, "/auth/email-password/signin",
		map[string]string{"email": email, "password": pw}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("signin: %d body=%s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "totp_required") {
		t.Fatalf("signin body should declare totp_required; got %s", body)
	}
	pending := resp.Cookies()

	// 6. /auth/me must be 401 with a pending session, emitted as RFC 7807
	// problem+json with a step_up_required code so frontends can distinguish
	// "need to log in" from "need to complete second factor" without
	// special-casing string bodies (v2.5 contract).
	meReq, _ := http.NewRequest("GET", srv.URL+"/auth/me", nil)
	for _, c := range pending {
		meReq.AddCookie(c)
	}
	meResp, _ := http.DefaultClient.Do(meReq)
	if meResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/auth/me with pending session should be 401; got %d", meResp.StatusCode)
	}
	if ct := meResp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("/auth/me 401 must be problem+json; got Content-Type=%q", ct)
	}
	if wa := meResp.Header.Get("WWW-Authenticate"); !strings.Contains(wa, "auth.step_up_required") {
		t.Fatalf(`/auth/me 401 WWW-Authenticate must include "auth.step_up_required"; got %q`, wa)
	}
	meBody, _ := io.ReadAll(meResp.Body)
	_ = meResp.Body.Close()
	if !strings.Contains(string(meBody), `"code":"auth.step_up_required"`) {
		t.Fatalf(`/auth/me 401 body must include "auth.step_up_required" code; got %s`, meBody)
	}

	// 7. Verify TOTP. Use a fresh current code (skew tolerance covers any
	// few-second drift between the enroll and the verify call).
	verifyCode, _ := totp.GenerateCode(enroll.Secret, time.Now())
	resp, body = postJSONWithCookies(t, srv, "/auth/totp/verify",
		map[string]string{"code": verifyCode}, pending)
	if resp.StatusCode != 200 {
		t.Fatalf("verify: %d body=%s", resp.StatusCode, string(body))
	}

	// 8. /auth/me now succeeds with the same cookie (server promoted it
	// in place and re-emitted the cookie with the same value).
	meReq2, _ := http.NewRequest("GET", srv.URL+"/auth/me", nil)
	for _, c := range pending {
		meReq2.AddCookie(c)
	}
	meResp2, _ := http.DefaultClient.Do(meReq2)
	if meResp2.StatusCode != 200 {
		t.Fatalf("/auth/me after verify should be 200; got %d", meResp2.StatusCode)
	}
	_ = meResp2.Body.Close()
}

// TestRecoveryStepUpFlow exercises the same flow but uses a recovery code
// instead of a TOTP code at verify time.
func TestRecoveryStepUpFlow(t *testing.T) {
	srv, _ := newTOTPServer(t)
	email := "rec@h.com"
	pw := "twelve-chars-min-pw"

	resp, _ := postJSONWithCookies(t, srv, "/auth/email-password/signup",
		map[string]string{"email": email, "password": pw}, nil)
	full := resp.Cookies()
	resp, body := postJSONWithCookies(t, srv, "/auth/totp/enroll/begin", struct{}{}, full)
	if resp.StatusCode != 200 {
		t.Fatalf("enroll/begin: %d", resp.StatusCode)
	}
	var enroll struct {
		Secret       string `json:"secret"`
		EnrollmentID string `json:"enrollmentId"`
	}
	_ = json.Unmarshal(body, &enroll)
	code, _ := totp.GenerateCode(enroll.Secret, time.Now())
	_, body = postJSONWithCookies(t, srv, "/auth/totp/enroll/finish",
		map[string]string{"enrollmentId": enroll.EnrollmentID, "code": code}, full)
	var rcResp struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	_ = json.Unmarshal(body, &rcResp)

	// Logout, sign back in (gets pending), then recover.
	logoutReq, _ := http.NewRequest("DELETE", srv.URL+"/auth/sessions/current", nil)
	for _, c := range full {
		logoutReq.AddCookie(c)
	}
	r2, _ := http.DefaultClient.Do(logoutReq)
	_ = r2.Body.Close()

	resp, _ = postJSONWithCookies(t, srv, "/auth/email-password/signin",
		map[string]string{"email": email, "password": pw}, nil)
	pending := resp.Cookies()

	resp, body = postJSONWithCookies(t, srv, "/auth/totp/recovery",
		map[string]string{"code": rcResp.RecoveryCodes[0]}, pending)
	if resp.StatusCode != 200 {
		t.Fatalf("recovery: %d body=%s", resp.StatusCode, string(body))
	}
	meReq, _ := http.NewRequest("GET", srv.URL+"/auth/me", nil)
	for _, c := range pending {
		meReq.AddCookie(c)
	}
	meResp, _ := http.DefaultClient.Do(meReq)
	if meResp.StatusCode != 200 {
		t.Fatalf("/auth/me after recovery should be 200; got %d", meResp.StatusCode)
	}
	_ = meResp.Body.Close()
}
