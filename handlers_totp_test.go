package theauth_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
)

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

	// 6. /auth/me must be 401 with a pending session.
	meReq, _ := http.NewRequest("GET", srv.URL+"/auth/me", nil)
	for _, c := range pending {
		meReq.AddCookie(c)
	}
	meResp, _ := http.DefaultClient.Do(meReq)
	if meResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/auth/me with pending session should be 401; got %d", meResp.StatusCode)
	}
	_ = meResp.Body.Close()

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
