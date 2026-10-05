package theauth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
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

func hardenedAuth(t *testing.T, mutate func(*theauth.Config)) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cfg := theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		EncryptionKey:     key,
		TOTP:              &theauth.TOTPConfig{Issuer: "T"},
		RateLimitPerIP:    10000,
		RateLimitPerEmail: 10000,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := theauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, store
}

func codeOf(t *testing.T, err error) string {
	t.Helper()
	var te *theauth.TheAuthError
	if !errors.As(err, &te) {
		t.Fatalf("want TheAuthError, got %v", err)
	}
	return te.Code
}

func hpost(t *testing.T, h http.Handler, path, ip string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.RemoteAddr = ip + ":4000"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mounted(a *theauth.TheAuth) http.Handler {
	r := chi.NewRouter()
	a.Mount(r)
	return r
}

func errBody(t *testing.T, rec *httptest.ResponseRecorder) (code, msg string) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Fatalf("content-type %q, body %q", ct, rec.Body.String())
	}
	var b struct{ Code, Message, Detail string }
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("body not json: %q", rec.Body.String())
	}
	return b.Code, b.Message + b.Detail
}

func TestLoginThrottleUnknownAndKnownUsersBehaveAlike(t *testing.T) {
	a, _ := hardenedAuth(t, func(c *theauth.Config) {
		c.LoginThrottle = &theauth.LoginThrottleConfig{GraceFailures: 2, BaseDelay: time.Hour, UserMaxFailures: 1000}
	})
	ctx := context.Background()
	if _, _, err := theauth.SignupWithPasswordForTest(a, ctx, "known@h.com", validPassword); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"known@h.com", "ghost@h.com"} {
		t.Run(email, func(t *testing.T) {
			for i := 0; i < 2; i++ {
				_, _, err := theauth.SigninWithPasswordForTest(a, ctx, email, "wrong-wrong-wrong", "ua", "7.7.7.7")
				if c := codeOf(t, err); c != theauth.CodeInvalidCredentials {
					t.Fatalf("attempt %d: %s", i, c)
				}
			}
			_, _, err := theauth.SigninWithPasswordForTest(a, ctx, email, "wrong-wrong-wrong", "ua", "7.7.7.7")
			if c := codeOf(t, err); c != theauth.CodeInvalidCredentials {
				t.Fatalf("third attempt: %s", c)
			}
			_, _, err = theauth.SigninWithPasswordForTest(a, ctx, email, validPassword, "ua", "7.7.7.7")
			var te *theauth.TheAuthError
			if !errors.As(err, &te) || te.Code != theauth.CodeRateLimited || te.RetryAfter <= 0 {
				t.Fatalf("want rate_limited with RetryAfter, got %v", err)
			}
		})
	}
	if _, _, err := theauth.SigninWithPasswordForTest(a, ctx, "known@h.com", validPassword, "ua", "8.8.8.8"); err != nil {
		t.Fatalf("other ip must not be throttled: %v", err)
	}
}

func TestUserLockoutAcrossIPsAndAdminUnlock(t *testing.T) {
	a, _ := hardenedAuth(t, func(c *theauth.Config) {
		c.LoginThrottle = &theauth.LoginThrottleConfig{GraceFailures: 1000, UserMaxFailures: 3, UserLockout: time.Hour}
	})
	ctx := context.Background()
	if _, _, err := theauth.SignupWithPasswordForTest(a, ctx, "lock@h.com", validPassword); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _, _ = theauth.SigninWithPasswordForTest(a, ctx, "lock@h.com", "nope-nope-nope-nope", "ua", "10.0.0."+string(rune('1'+i)))
	}
	_, _, err := theauth.SigninWithPasswordForTest(a, ctx, "lock@h.com", validPassword, "ua", "10.9.9.9")
	if c := codeOf(t, err); c != theauth.CodeAccountLocked {
		t.Fatalf("want account_locked, got %s", c)
	}
	if err := a.UnlockUser(ctx, " LOCK@h.com "); err != nil {
		t.Fatal(err)
	}
	if _, _, err := theauth.SigninWithPasswordForTest(a, ctx, "lock@h.com", validPassword, "ua", "10.9.9.9"); err != nil {
		t.Fatalf("signin after unlock: %v", err)
	}
}

func TestLoginThrottleDisabled(t *testing.T) {
	a, _ := hardenedAuth(t, func(c *theauth.Config) {
		c.LoginThrottle = &theauth.LoginThrottleConfig{Disabled: true}
	})
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		_, _, err := theauth.SigninWithPasswordForTest(a, ctx, "x@h.com", "wrong-wrong-wrong", "ua", "1.1.1.1")
		if c := codeOf(t, err); c != theauth.CodeInvalidCredentials {
			t.Fatalf("attempt %d: %s", i, c)
		}
	}
}

func enrollTOTP(t *testing.T, a *theauth.TheAuth, email string) (theauth.User, string) {
	t.Helper()
	ctx := context.Background()
	u, _, err := theauth.SignupWithPasswordForTest(a, ctx, email, validPassword)
	if err != nil {
		t.Fatal(err)
	}
	res, err := theauth.BeginTOTPEnrollmentForTest(a, ctx, u.ID, email)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(res.Secret, time.Now())
	if _, err := theauth.FinishTOTPEnrollmentForTest(a, ctx, u.ID, res.EnrollmentID, code); err != nil {
		t.Fatal(err)
	}
	return *u, res.Secret
}

func TestTOTPReplayRejected(t *testing.T) {
	a, _ := hardenedAuth(t, nil)
	ctx := context.Background()
	u, secret := enrollTOTP(t, a, "replay@h.com")
	code, _ := totp.GenerateCode(secret, time.Now())

	tok1, _, err := theauth.IssuePending2FAForTest(a, ctx, u.ID, "ua", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := theauth.VerifyTOTPForTest(a, ctx, tok1, code); err != nil {
		t.Fatalf("first use: %v", err)
	}
	tok2, _, _ := theauth.IssuePending2FAForTest(a, ctx, u.ID, "ua", "")
	_, _, err = theauth.VerifyTOTPForTest(a, ctx, tok2, code)
	if c := codeOf(t, err); c != theauth.CodeInvalidTOTP {
		t.Fatalf("replayed code: got %s", c)
	}
}

func TestMFAAttemptCapHoldsAcrossFreshPendingSessions(t *testing.T) {
	a, _ := hardenedAuth(t, func(c *theauth.Config) {
		c.LoginThrottle = &theauth.LoginThrottleConfig{MFAMaxFailures: 5, MFALockout: time.Hour}
	})
	ctx := context.Background()
	u, secret := enrollTOTP(t, a, "mfa@h.com")

	var invalid, locked int
	for i := 0; i < 25; i++ {
		tok, _, err := theauth.IssuePending2FAForTest(a, ctx, u.ID, "ua", "")
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = theauth.VerifyTOTPForTest(a, ctx, tok, "000000")
		switch codeOf(t, err) {
		case theauth.CodeInvalidTOTP:
			invalid++
		case theauth.CodeAccountLocked:
			locked++
		}
	}
	if invalid > 5 {
		t.Fatalf("%d guesses reached validation, cap is 5", invalid)
	}
	if locked != 25-invalid {
		t.Fatalf("invalid=%d locked=%d", invalid, locked)
	}

	good, _ := totp.GenerateCode(secret, time.Now())
	tok, _, _ := theauth.IssuePending2FAForTest(a, ctx, u.ID, "ua", "")
	_, _, err := theauth.VerifyTOTPForTest(a, ctx, tok, good)
	if c := codeOf(t, err); c != theauth.CodeAccountLocked {
		t.Fatalf("correct code during lockout: %s", c)
	}
	_, _, err = theauth.ConsumeRecoveryCodeForTest(a, ctx, tok, "abcdef0123")
	if c := codeOf(t, err); c != theauth.CodeAccountLocked {
		t.Fatalf("recovery during lockout: %s", c)
	}

	if err := a.UnlockUser(ctx, "mfa@h.com"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := theauth.VerifyTOTPForTest(a, ctx, tok, good); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
}

func TestRecoveryCodeGuessesShareTheMFACap(t *testing.T) {
	a, _ := hardenedAuth(t, func(c *theauth.Config) {
		c.LoginThrottle = &theauth.LoginThrottleConfig{MFAMaxFailures: 3, MFALockout: time.Hour}
	})
	ctx := context.Background()
	u, secret := enrollTOTP(t, a, "rc@h.com")
	for i := 0; i < 3; i++ {
		tok, _, _ := theauth.IssuePending2FAForTest(a, ctx, u.ID, "ua", "")
		_, _, err := theauth.ConsumeRecoveryCodeForTest(a, ctx, tok, "0000000000")
		if c := codeOf(t, err); c != theauth.CodeInvalidTOTP {
			t.Fatalf("guess %d: %s", i, c)
		}
	}
	good, _ := totp.GenerateCode(secret, time.Now())
	tok, _, _ := theauth.IssuePending2FAForTest(a, ctx, u.ID, "ua", "")
	if _, _, err := theauth.VerifyTOTPForTest(a, ctx, tok, good); codeOf(t, err) != theauth.CodeAccountLocked {
		t.Fatal("recovery failures must lock totp too")
	}
}

func TestEmailCanonicalization(t *testing.T) {
	tests := []struct {
		name      string
		nfkc      bool
		signup    string
		signin    string
		wantLogin bool
	}{
		{"case and spaces", false, "Mixed@Case.COM", "  mixed@case.com ", true},
		{"fullwidth distinct without nfkc", false, "ｕｓｅｒ@h.com", "user@h.com", false},
		{"fullwidth folds with nfkc", true, "ｕｓｅｒ@h.com", "user@h.com", true},
		{"nfkc case and spaces", true, " USER2@H.com", "user2@h.com", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := hardenedAuth(t, func(c *theauth.Config) { c.EmailNFKC = tc.nfkc })
			ctx := context.Background()
			if _, _, err := theauth.SignupWithPasswordForTest(a, ctx, tc.signup, validPassword); err != nil {
				t.Fatal(err)
			}
			_, _, err := theauth.SigninWithPasswordForTest(a, ctx, tc.signin, validPassword, "ua", "")
			if (err == nil) != tc.wantLogin {
				t.Fatalf("signin err=%v wantLogin=%v", err, tc.wantLogin)
			}
			_, _, err = theauth.SignupWithPasswordForTest(a, ctx, tc.signin, validPassword)
			if tc.wantLogin && codeOf(t, err) != theauth.CodeEmailTaken {
				t.Fatalf("duplicate signup must be email_taken, got %v", err)
			}
		})
	}
}

func TestEmailCanonicalizationMagicLinkAndReset(t *testing.T) {
	a, store := hardenedAuth(t, func(c *theauth.Config) { c.EmailNFKC = true })
	ctx := context.Background()
	tok, err := theauth.RequestMagicLinkForTest(a, ctx, "  ＭＬ@H.com ")
	if err != nil {
		t.Fatal(err)
	}
	_, u, err := theauth.ConsumeMagicLinkForTest(a, ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "ml@h.com" {
		t.Fatalf("magic link user email %q", u.Email)
	}
	if got, err := store.UserByEmail(ctx, "ml@h.com"); err != nil || got == nil {
		t.Fatalf("lookup canonical: %v", err)
	}
	if a.NormalizeEmail(" ＡＢ@H.com ") != "ab@h.com" {
		t.Fatal("NormalizeEmail")
	}
}

func TestPasswordPolicy(t *testing.T) {
	tests := []struct {
		name string
		pw   string
		ok   bool
	}{
		{"short", "short", false},
		{"ok", validPassword, true},
		{"exactly 72 bytes", strings.Repeat("a", 72), true},
		{"73 bytes", strings.Repeat("a", 73), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := hardenedAuth(t, nil)
			rec := hpost(t, mounted(a), "/auth/email-password/signup", "1.1.1.1",
				map[string]string{"email": "p@h.com", "password": tc.pw}, nil)
			if tc.ok {
				if rec.Code != http.StatusCreated {
					t.Fatalf("status %d body %s", rec.Code, rec.Body)
				}
				return
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400 body %s", rec.Code, rec.Body)
			}
			if c, _ := errBody(t, rec); c != theauth.CodeWeakPassword {
				t.Fatalf("code %q", c)
			}
		})
	}
}

type fakeBreach struct {
	breached bool
	err      error
}

func (f fakeBreach) IsBreached(context.Context, string) (bool, error) { return f.breached, f.err }

func TestPasswordBreachCheckHook(t *testing.T) {
	tests := []struct {
		name    string
		checker theauth.BreachChecker
		wantErr bool
	}{
		{"off", nil, false},
		{"breached", fakeBreach{breached: true}, true},
		{"clean", fakeBreach{}, false},
		{"network error fails open", fakeBreach{err: errors.New("down")}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := hardenedAuth(t, func(c *theauth.Config) { c.PasswordPolicy.BreachChecker = tc.checker })
			_, _, err := theauth.SignupWithPasswordForTest(a, context.Background(), "b@h.com", validPassword)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && codeOf(t, err) != theauth.CodeWeakPassword {
				t.Fatalf("wrong code: %v", err)
			}
		})
	}
}

func TestBootstrapSetupTokenFlow(t *testing.T) {
	a, _ := hardenedAuth(t, func(c *theauth.Config) {
		c.Bootstrap = &theauth.BootstrapConfig{SetupToken: "s3cret-token", SuppressSetupTokenLog: true}
	})
	h := mounted(a)
	body := map[string]string{"email": "admin@h.com", "password": validPassword}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/bootstrap/status", nil))
	if !strings.Contains(rec.Body.String(), `"needsSetup":true`) {
		t.Fatalf("status %s", rec.Body)
	}

	rec = hpost(t, h, "/auth/email-password/signup", "1.1.1.1", body, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no token: %d %s", rec.Code, rec.Body)
	}
	if c, _ := errBody(t, rec); c != theauth.CodeSetupTokenInvalid {
		t.Fatalf("code %q", c)
	}
	rec = hpost(t, h, "/auth/email-password/signup", "1.1.1.1", body, map[string]string{"X-Setup-Token": "wrong"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad token: %d", rec.Code)
	}
	if a.SetupToken() != "s3cret-token" {
		t.Fatal("SetupToken accessor")
	}

	rec = hpost(t, h, "/auth/email-password/signup", "1.1.1.1", body, map[string]string{"X-Setup-Token": "s3cret-token"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("good token: %d %s", rec.Code, rec.Body)
	}

	rec = hpost(t, h, "/auth/email-password/signup", "1.1.1.1",
		map[string]string{"email": "second@h.com", "password": validPassword, "setupToken": "s3cret-token"}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("second signup: %d", rec.Code)
	}
	if c, _ := errBody(t, rec); c != theauth.CodeSignupClosed {
		t.Fatalf("code %q", c)
	}
	if a.SetupToken() != "" {
		t.Fatal("token must be cleared after first user")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/bootstrap/status", nil))
	if !strings.Contains(rec.Body.String(), `"needsSetup":false`) {
		t.Fatalf("status after %s", rec.Body)
	}
	if _, err := theauth.RequestMagicLinkForTest(a, context.Background(), "new@h.com"); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapGeneratedTokenAndOptions(t *testing.T) {
	t.Run("generated token and magic link refused", func(t *testing.T) {
		a, _ := hardenedAuth(t, func(c *theauth.Config) {
			c.Bootstrap = &theauth.BootstrapConfig{SuppressSetupTokenLog: true}
		})
		if len(a.SetupToken()) < 32 {
			t.Fatalf("generated token %q", a.SetupToken())
		}
		tok, _ := theauth.RequestMagicLinkForTest(a, context.Background(), "m@h.com")
		_, _, err := theauth.ConsumeMagicLinkForTest(a, context.Background(), tok)
		if codeOf(t, err) != theauth.CodeSetupTokenInvalid {
			t.Fatalf("magic link must not bypass setup token: %v", err)
		}
	})
	t.Run("open signup after first user and OnFirstUser", func(t *testing.T) {
		var first string
		a, _ := hardenedAuth(t, func(c *theauth.Config) {
			c.Bootstrap = &theauth.BootstrapConfig{
				SetupToken: "tok", OpenSignupAfterFirstUser: true,
				OnFirstUser: func(_ context.Context, u *theauth.User) error { first = u.Email; return nil },
			}
		})
		h := mounted(a)
		hpost(t, h, "/auth/email-password/signup", "1.1.1.1",
			map[string]string{"email": "a@h.com", "password": validPassword}, map[string]string{"X-Setup-Token": "tok"})
		if first != "a@h.com" {
			t.Fatalf("OnFirstUser got %q", first)
		}
		rec := hpost(t, h, "/auth/email-password/signup", "1.1.1.1",
			map[string]string{"email": "b@h.com", "password": validPassword}, nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("open signup: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("existing users skip token", func(t *testing.T) {
		store := memory.New()
		if _, err := store.CreateUser(context.Background(), theauth.User{Email: "old@h.com"}); err != nil {
			t.Fatal(err)
		}
		a, err := theauth.New(theauth.Config{Storage: store, BaseURL: "http://x", Bootstrap: &theauth.BootstrapConfig{}})
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		if a.SetupToken() != "" {
			t.Fatal("no token expected when users exist")
		}
		n, err := a.UserCount(context.Background())
		if err != nil || n != 1 {
			t.Fatalf("UserCount=%d err=%v", n, err)
		}
	})
}

func TestSetupTokenGuessesAreThrottled(t *testing.T) {
	a, _ := hardenedAuth(t, func(c *theauth.Config) {
		c.Bootstrap = &theauth.BootstrapConfig{SetupToken: "right", SuppressSetupTokenLog: true}
		c.LoginThrottle = &theauth.LoginThrottleConfig{GraceFailures: 2, BaseDelay: time.Hour}
	})
	h := mounted(a)
	body := map[string]string{"email": "a@h.com", "password": validPassword}
	var last *httptest.ResponseRecorder
	for i := 0; i < 4; i++ {
		last = hpost(t, h, "/auth/email-password/signup", "5.5.5.5", body, map[string]string{"X-Setup-Token": "guess"})
	}
	if last.Code != http.StatusTooManyRequests || last.Header().Get("Retry-After") == "" {
		t.Fatalf("status %d retry-after %q", last.Code, last.Header().Get("Retry-After"))
	}
	if rec := hpost(t, h, "/auth/email-password/signup", "6.6.6.6", body, map[string]string{"X-Setup-Token": "right"}); rec.Code != http.StatusCreated {
		t.Fatalf("operator on another ip: %d", rec.Code)
	}
}

func TestBootstrapRequiresUserCountStorage(t *testing.T) {
	_, err := theauth.New(theauth.Config{CoreStorage: coreOnly{memory.New()}, BaseURL: "http://x", Bootstrap: &theauth.BootstrapConfig{}})
	if !errors.Is(err, theauth.ErrStorageMissingCapability) {
		t.Fatalf("got %v", err)
	}
}

func TestResetPasswordAdmin(t *testing.T) {
	a, _ := hardenedAuth(t, func(c *theauth.Config) {
		c.LoginThrottle = &theauth.LoginThrottleConfig{GraceFailures: 1000, UserMaxFailures: 2, UserLockout: time.Hour}
	})
	ctx := context.Background()
	u, sess, err := theauth.SignupWithPasswordForTest(a, ctx, "rec@h.com", validPassword)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		_, _, _ = theauth.SigninWithPasswordForTest(a, ctx, "rec@h.com", "bad-bad-bad-bad-bad", "ua", "1.1.1.1")
	}
	if err := a.ResetPasswordAdmin(ctx, "REC@h.com", "short"); codeOf(t, err) != theauth.CodeWeakPassword {
		t.Fatalf("policy must apply: %v", err)
	}
	if err := a.ResetPasswordAdmin(ctx, "REC@h.com", "brand-new-passphrase-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := theauth.ValidateSessionForTest(a, ctx, sess); err == nil {
		t.Fatal("old session must be revoked")
	}
	if _, _, err := theauth.SigninWithPasswordForTest(a, ctx, "rec@h.com", "brand-new-passphrase-1", "ua", "2.2.2.2"); err != nil {
		t.Fatalf("signin with new password (lockout cleared): %v", err)
	}
	if err := a.ResetPasswordAdmin(ctx, "nobody@h.com", "brand-new-passphrase-1"); err == nil {
		t.Fatal("unknown user must error")
	}
	_ = u
}

func TestPlainTextErrorsAreNowJSON(t *testing.T) {
	a, _ := hardenedAuth(t, func(c *theauth.Config) {
		c.WebAuthn = nil
	})
	h := mounted(a)
	tests := []struct {
		name   string
		do     func() *httptest.ResponseRecorder
		status int
		code   string
	}{
		{"me unauthenticated", func() *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
			h.ServeHTTP(rec, req)
			return rec
		}, http.StatusUnauthorized, ""},
		{"magic link bad body", func() *httptest.ResponseRecorder {
			return hpost(t, h, "/auth/magic-link", "1.1.1.1", "not-an-object", nil)
		}, http.StatusBadRequest, theauth.CodeBadRequest},
		{"signup bad body", func() *httptest.ResponseRecorder {
			return hpost(t, h, "/auth/email-password/signup", "1.1.1.1", map[string]string{}, nil)
		}, http.StatusBadRequest, theauth.CodeBadRequest},
		{"magic verify missing token", func() *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify", nil))
			return rec
		}, http.StatusBadRequest, theauth.CodeBadRequest},
		{"totp verify missing session", func() *httptest.ResponseRecorder {
			return hpost(t, h, "/auth/totp/verify", "1.1.1.1", map[string]string{"code": "1"}, nil)
		}, http.StatusUnauthorized, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := tc.do()
			if rec.Code != tc.status {
				t.Fatalf("status %d want %d body %q", rec.Code, tc.status, rec.Body)
			}
			code, msg := errBody(t, rec)
			if msg == "" || (tc.code != "" && code != tc.code) {
				t.Fatalf("code %q msg %q", code, msg)
			}
		})
	}
}

func TestRateLimitMiddlewareReturnsJSON(t *testing.T) {
	a, _ := hardenedAuth(t, func(c *theauth.Config) { c.RateLimitPerIP = 1 })
	h := mounted(a)
	var rec *httptest.ResponseRecorder
	for i := 0; i < 3; i++ {
		rec = hpost(t, h, "/auth/email-password/signup", "3.3.3.3", map[string]string{"email": "x@h.com", "password": "x"}, nil)
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d", rec.Code)
	}
	if code, _ := errBody(t, rec); code != theauth.CodeRateLimited {
		t.Fatalf("code %q", code)
	}
}

func TestThrottleHTTPSetsRetryAfter(t *testing.T) {
	a, _ := hardenedAuth(t, func(c *theauth.Config) {
		c.LoginThrottle = &theauth.LoginThrottleConfig{GraceFailures: 1, BaseDelay: 90 * time.Second}
	})
	h := mounted(a)
	var rec *httptest.ResponseRecorder
	for i := 0; i < 3; i++ {
		rec = hpost(t, h, "/auth/email-password/signin", "4.4.4.4", map[string]string{"email": "g@h.com", "password": "nope-nope-nope"}, nil)
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d", rec.Code)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Fatal("missing Retry-After")
	}
}
