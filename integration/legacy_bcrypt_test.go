package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/integration/internal/testutil"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"golang.org/x/crypto/bcrypt"
)

func legacyAuth(t *testing.T, allow bool, throttle *theauth.LoginThrottleConfig) (*theauth.TheAuth, *memory.Store, theauth.User) {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
		PasswordPolicy: theauth.PasswordPolicyConfig{AllowLegacyBcrypt: allow},
		LoginThrottle:  throttle,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	ctx := context.Background()
	u, err := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "legacy@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(validPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetUserPassword(ctx, u.ID, string(h)); err != nil {
		t.Fatal(err)
	}
	return a, store, u
}

func invalidCreds(t *testing.T, err error) {
	t.Helper()
	var te *theauth.TheAuthError
	if !errors.As(err, &te) || te.Code != theauth.CodeInvalidCredentials {
		t.Fatalf("want invalid credentials, got %v", err)
	}
}

func TestLegacyBcryptSignin(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		allow    bool
		password string
		wantOK   bool
		rehashed bool
	}{
		{"flag on, right password", true, validPassword, true, true},
		{"flag on, wrong password", true, "wrong-password-entirely", false, false},
		{"flag off, right password", false, validPassword, false, false},
		{"flag off, wrong password", false, "wrong-password-entirely", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, store, u := legacyAuth(t, tc.allow, nil)
			_, _, err := testutil.SigninWithPasswordForTest(a, ctx, "legacy@h.com", tc.password, "ua", "")
			if tc.wantOK {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				invalidCreds(t, err)
			}
			h, _ := store.UserPasswordHashByID(ctx, u.ID)
			if got := strings.HasPrefix(h, "$argon2id$"); got != tc.rehashed {
				t.Fatalf("argon2id stored = %v, want %v (hash %.12s)", got, tc.rehashed, h)
			}
			if tc.rehashed {
				if _, _, err := testutil.SigninWithPasswordForTest(a, ctx, "legacy@h.com", tc.password, "ua", ""); err != nil {
					t.Fatalf("second login on argon2id: %v", err)
				}
				h2, _ := store.UserPasswordHashByID(ctx, u.ID)
				if h2 != h {
					t.Fatal("hash changed on second login")
				}
			}
		})
	}
}

func TestLegacyBcryptWrongPasswordMatchesArgon2Error(t *testing.T) {
	ctx := context.Background()
	a, _, _ := legacyAuth(t, true, nil)
	_, _, errB := testutil.SigninWithPasswordForTest(a, ctx, "legacy@h.com", "wrong-password-entirely", "ua", "")
	if _, _, err := testutil.SignupWithPasswordForTest(a, ctx, "argon@h.com", validPassword); err != nil {
		t.Fatal(err)
	}
	_, _, errA := testutil.SigninWithPasswordForTest(a, ctx, "argon@h.com", "wrong-password-entirely", "ua", "")
	if errB == nil || errA == nil || errB.Error() != errA.Error() {
		t.Fatalf("errors differ: %v vs %v", errB, errA)
	}
}

func TestLegacyBcryptLockoutStillApplies(t *testing.T) {
	ctx := context.Background()
	a, _, _ := legacyAuth(t, true, &theauth.LoginThrottleConfig{UserMaxFailures: 2, GraceFailures: 100, UserLockout: time.Hour})
	for i := 0; i < 2; i++ {
		_, _, err := testutil.SigninWithPasswordForTest(a, ctx, "legacy@h.com", "wrong-password-entirely", "ua", "")
		invalidCreds(t, err)
	}
	_, _, err := testutil.SigninWithPasswordForTest(a, ctx, "legacy@h.com", validPassword, "ua", "")
	if err == nil {
		t.Fatal("expected lockout to reject the correct password")
	}
}

func TestLegacyBcryptStepUpAndChangePassword(t *testing.T) {
	ctx := context.Background()
	for _, allow := range []bool{true, false} {
		a, store, u := legacyAuth(t, allow, nil)
		_, sess, err := testutil.IssueSessionForTest(a, ctx, u, "ua", "")
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.StepUp(ctx, &sess, theauth.StepUpInput{Method: theauth.StepUpMethodPassword, Password: validPassword})
		h, _ := store.UserPasswordHashByID(ctx, u.ID)
		if allow {
			if err != nil || !strings.HasPrefix(h, "$argon2id$") {
				t.Fatalf("step-up with flag on: err=%v hash=%.12s", err, h)
			}
		} else {
			invalidCreds(t, err)
			if _, err = a.ChangePassword(ctx, sess, validPassword, "another-long-password-1"); err == nil {
				t.Fatal("change password must fail with flag off")
			}
			invalidCreds(t, err)
		}
		if allow {
			if _, err := a.ChangePassword(ctx, sess, validPassword, "another-long-password-1"); err != nil {
				t.Fatalf("change password with flag on: %v", err)
			}
		}
	}
}
