package integration

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/integration/internal/testutil"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/pquerna/otp/totp"
)

type hookError struct {
	hook string
	err  error
}

type hookRecorder struct {
	mu      sync.Mutex
	signins []theauth.Session
	mfa     []theauth.MFAKind
	errs    []hookError
}

func (r *hookRecorder) hooks() *theauth.LifecycleHooks {
	return &theauth.LifecycleHooks{
		OnSignin: func(_ context.Context, _ *theauth.User, s *theauth.Session) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.signins = append(r.signins, *s)
			return nil
		},
		OnMFAEnabled: func(_ context.Context, _ *theauth.User, k theauth.MFAKind) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.mfa = append(r.mfa, k)
			return nil
		},
		OnHookError: func(_ context.Context, hook string, err error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.errs = append(r.errs, hookError{hook, err})
		},
	}
}

func newHookTOTPAuth(t *testing.T, h *theauth.LifecycleHooks) *theauth.TheAuth {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:           memory.New(),
		BaseURL:           "http://localhost",
		EncryptionKey:     key,
		TOTP:              &theauth.TOTPConfig{Issuer: "Hooks"},
		RateLimitPerIP:    1000,
		RateLimitPerEmail: 1000,
		LifecycleHooks:    h,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

// TestLifecycleHooks_TOTPSigninAndEnable proves OnMFAEnabled fires on TOTP
// enrollment and that a password sign-in held at pending_2fa fires
// OnSignin exactly once, when the TOTP or recovery-code step completes it.
func TestLifecycleHooks_TOTPSigninAndEnable(t *testing.T) {
	tests := []struct {
		name     string
		complete func(t *testing.T, a *theauth.TheAuth, pending string, secret string, codes []string) theauth.Session
	}{
		{"totp code completes sign-in", func(t *testing.T, a *theauth.TheAuth, pending, secret string, _ []string) theauth.Session {
			code, _ := totp.GenerateCode(secret, time.Now())
			_, sess, err := testutil.VerifyTOTPForTest(a, context.Background(), pending, code)
			if err != nil {
				t.Fatal(err)
			}
			return sess
		}},
		{"recovery code completes sign-in", func(t *testing.T, a *theauth.TheAuth, pending, _ string, codes []string) theauth.Session {
			_, sess, err := testutil.ConsumeRecoveryCodeForTest(a, context.Background(), pending, codes[0])
			if err != nil {
				t.Fatal(err)
			}
			return sess
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &hookRecorder{}
			a := newHookTOTPAuth(t, rec.hooks())
			ctx := context.Background()
			u, _, err := testutil.SignupWithPasswordForTest(a, ctx, "mfa@h.com", "twelve-chars-min-pw")
			if err != nil {
				t.Fatal(err)
			}
			enr, err := testutil.BeginTOTPEnrollmentForTest(a, ctx, u.ID, "mfa@h.com")
			if err != nil {
				t.Fatal(err)
			}
			code, _ := totp.GenerateCode(enr.Secret, time.Now())
			codes, err := testutil.FinishTOTPEnrollmentForTest(a, ctx, u.ID, enr.EnrollmentID, code)
			if err != nil {
				t.Fatal(err)
			}
			if len(rec.mfa) != 1 || rec.mfa[0] != theauth.MFAKindTOTP {
				t.Fatalf("OnMFAEnabled: want [totp]; got %v", rec.mfa)
			}

			pending, _, err := testutil.IssuePending2FAForTest(a, ctx, u.ID, "ua", "")
			if err != nil {
				t.Fatal(err)
			}
			if len(rec.signins) != 0 {
				t.Fatalf("pending_2fa must not fire OnSignin; got %d", len(rec.signins))
			}
			sess := tc.complete(t, a, pending, enr.Secret, codes)
			if len(rec.signins) != 1 {
				t.Fatalf("OnSignin after second factor: want 1; got %d", len(rec.signins))
			}
			if rec.signins[0].UserID != u.ID || rec.signins[0].AuthLevel != theauth.AuthLevelFull {
				t.Fatalf("OnSignin session: want full session for user; got %+v", rec.signins[0])
			}
			if sess.UserID != u.ID {
				t.Fatalf("returned session user mismatch: %v", sess.UserID)
			}
		})
	}
}

// TestLifecycleHooks_OnHookError proves OnHookError receives hook errors
// and recovered panics without failing the request, and that a panicking
// OnHookError callback cannot break the request either.
func TestLifecycleHooks_OnHookError(t *testing.T) {
	boom := errors.New("provisioning failed")
	tests := []struct {
		name       string
		onSignup   func(context.Context, *theauth.User, theauth.SignupMethod) error
		onErrPanic bool
		wantErrs   int
		wantIs     error
	}{
		{"returned error is reported", func(context.Context, *theauth.User, theauth.SignupMethod) error { return boom }, false, 1, boom},
		{"panic is reported as an error", func(context.Context, *theauth.User, theauth.SignupMethod) error { panic("kaboom") }, false, 1, nil},
		{"nil error is not reported", func(context.Context, *theauth.User, theauth.SignupMethod) error { return nil }, false, 0, nil},
		{"panicking callback is contained", func(context.Context, *theauth.User, theauth.SignupMethod) error { return boom }, true, 1, boom},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var errs []hookError
			a, err := theauth.New(theauth.Config{
				Storage:           memory.New(),
				BaseURL:           "http://localhost",
				RateLimitPerIP:    100,
				RateLimitPerEmail: 100,
				LifecycleHooks: &theauth.LifecycleHooks{
					OnSignup: tc.onSignup,
					OnHookError: func(_ context.Context, hook string, err error) {
						errs = append(errs, hookError{hook, err})
						if tc.onErrPanic {
							panic("callback panic")
						}
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(a.Close)
			if _, _, err := testutil.SignupWithPasswordForTest(a, context.Background(), "e@h.com", "twelve-chars-min-pw"); err != nil {
				t.Fatalf("signup must succeed despite hook failure; got %v", err)
			}
			if len(errs) != tc.wantErrs {
				t.Fatalf("OnHookError calls: want %d; got %d", tc.wantErrs, len(errs))
			}
			if tc.wantErrs == 0 {
				return
			}
			if errs[0].hook != "OnSignup" {
				t.Fatalf("hook name: want OnSignup; got %q", errs[0].hook)
			}
			if tc.wantIs != nil && !errors.Is(errs[0].err, tc.wantIs) {
				t.Fatalf("error: want %v; got %v", tc.wantIs, errs[0].err)
			}
		})
	}
}
