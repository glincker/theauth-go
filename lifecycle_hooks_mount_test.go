package theauth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
)

// TestLifecycleHooksFireThroughRealHTTPMount proves OnSignup,
// OnPasswordChange, and OnMFAEnabled fire when driven through the actual
// a.Mount() HTTP routes, not just the internal *ForTest forwarders used by
// TestLifecycleHooks_PasswordSignupAndSignin. Before this fix,
// passwordhandlers/totphandlers/webauthnhandlers held the raw internal
// Service directly and called it without ever going through the
// hook-firing root forwarders, so LifecycleHooks silently never fired for
// any consumer using the batteries-included Mount() routes.
func TestLifecycleHooksFireThroughRealHTTPMount(t *testing.T) {
	store := memory.New()
	var (
		mu                  sync.Mutex
		signupCount         int
		signupMethod        theauth.SignupMethod
		passwordChangeCount int
		mfaEnabledCount     int
		mfaEnabledKind      theauth.MFAKind
	)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		SessionTTL:        time.Hour,
		MagicLinkTTL:      15 * time.Minute,
		RateLimitPerIP:    1000,
		RateLimitPerEmail: 1000,
		EncryptionKey:     key,
		TOTP:              &theauth.TOTPConfig{Issuer: "theauth-mount-hooks-test"},
		LifecycleHooks: &theauth.LifecycleHooks{
			OnSignup: func(ctx context.Context, user *theauth.User, method theauth.SignupMethod) error {
				mu.Lock()
				defer mu.Unlock()
				signupCount++
				signupMethod = method
				return nil
			},
			OnPasswordChange: func(ctx context.Context, user *theauth.User) error {
				mu.Lock()
				defer mu.Unlock()
				passwordChangeCount++
				return nil
			},
			OnMFAEnabled: func(ctx context.Context, user *theauth.User, kind theauth.MFAKind) error {
				mu.Lock()
				defer mu.Unlock()
				mfaEnabledCount++
				mfaEnabledKind = kind
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	defer srv.Close()
	theauth.SetBaseURLForTest(a, srv.URL)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	// --- Signup via the real /auth/email-password/signup HTTP route ---
	signupBody, _ := json.Marshal(map[string]string{"email": "mount-hooks@y.com", "password": "correct-horse-battery-staple"})
	resp, err := client.Post(srv.URL+"/auth/email-password/signup", "application/json", bytes.NewReader(signupBody))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("signup: got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	mu.Lock()
	if signupCount != 1 || signupMethod != theauth.SignupMethodPassword {
		t.Fatalf("OnSignup via Mount(): want count=1 method=password; got count=%d method=%q", signupCount, signupMethod)
	}
	mu.Unlock()

	// --- Password reset via the real /auth/email-password/reset HTTP route ---
	// The reset token is minted directly (bypassing email delivery, a
	// separately-tested concern) so this test isolates the HTTP reset
	// handler's hook wiring specifically.
	token, err := theauth.RequestPasswordResetForTest(a, context.Background(), "mount-hooks@y.com")
	if err != nil {
		t.Fatalf("RequestPasswordResetForTest: %v", err)
	}
	resetBody, _ := json.Marshal(map[string]string{"token": token, "newPassword": "second-correct-horse-battery"})
	resp, err = client.Post(srv.URL+"/auth/email-password/reset", "application/json", bytes.NewReader(resetBody))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset: got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	mu.Lock()
	if passwordChangeCount != 1 {
		t.Fatalf("OnPasswordChange via Mount(): want count=1; got %d", passwordChangeCount)
	}
	mu.Unlock()

	// Reset revokes every existing session, so the signup response's
	// cookie is now stale. Sign back in with the new password via the
	// real HTTP route to get a fresh session before exercising TOTP.
	signinBody, _ := json.Marshal(map[string]string{"email": "mount-hooks@y.com", "password": "second-correct-horse-battery"})
	signinResp, err := client.Post(srv.URL+"/auth/email-password/signin", "application/json", bytes.NewReader(signinBody))
	if err != nil {
		t.Fatal(err)
	}
	if signinResp.StatusCode != http.StatusOK {
		t.Fatalf("signin after reset: got %d", signinResp.StatusCode)
	}
	_ = signinResp.Body.Close()

	// --- TOTP enrollment via the real /auth/totp/enroll/* HTTP routes ---
	// The fresh session cookie rides along automatically via the client's
	// cookie jar, satisfying RequireAuth.
	beginResp, err := client.Post(srv.URL+"/auth/totp/enroll/begin", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if beginResp.StatusCode != http.StatusOK {
		t.Fatalf("enroll/begin: got %d", beginResp.StatusCode)
	}
	var enroll struct {
		Secret       string `json:"secret"`
		EnrollmentID string `json:"enrollmentId"`
	}
	decodeErr := json.NewDecoder(beginResp.Body).Decode(&enroll)
	_ = beginResp.Body.Close()
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}

	code, err := totp.GenerateCode(enroll.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	finishBody, _ := json.Marshal(map[string]string{"enrollmentId": enroll.EnrollmentID, "code": code})
	finishResp, err := client.Post(srv.URL+"/auth/totp/enroll/finish", "application/json", bytes.NewReader(finishBody))
	if err != nil {
		t.Fatal(err)
	}
	if finishResp.StatusCode != http.StatusOK {
		t.Fatalf("enroll/finish: got %d", finishResp.StatusCode)
	}
	_ = finishResp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if mfaEnabledCount != 1 || mfaEnabledKind != theauth.MFAKindTOTP {
		t.Fatalf("OnMFAEnabled via Mount(): want count=1 kind=totp; got count=%d kind=%q", mfaEnabledCount, mfaEnabledKind)
	}
}
