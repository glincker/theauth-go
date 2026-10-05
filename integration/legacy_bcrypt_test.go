package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
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

type failingSetStore struct {
	*memory.Store
}

func (failingSetStore) SetUserPassword(context.Context, theauth.ULID, string) error {
	return errors.New("persist down")
}

type legacyCall struct{ userID, hash string }

func legacyCallbackAuth(t *testing.T, allow, argon, failPersist bool, cb func(string, string)) (*theauth.TheAuth, theauth.User) {
	t.Helper()
	mem := memory.New()
	var st theauth.Storage = mem
	if failPersist {
		st = failingSetStore{mem}
	}
	a, err := theauth.New(theauth.Config{
		Storage: st, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
		PasswordPolicy: theauth.PasswordPolicyConfig{AllowLegacyBcrypt: allow, OnLegacyHashAccepted: cb},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	ctx := context.Background()
	u, err := mem.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "legacy@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if argon {
		if err := mem.SetUserPassword(ctx, u.ID, mustArgon(t)); err != nil {
			t.Fatal(err)
		}
		return a, u
	}
	h, err := bcrypt.GenerateFromPassword([]byte(validPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.SetUserPassword(ctx, u.ID, string(h)); err != nil {
		t.Fatal(err)
	}
	return a, u
}

func mustArgon(t *testing.T) string {
	t.Helper()
	h, err := crypto.HashPassword(validPassword)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestOnLegacyHashAcceptedCallback(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name        string
		allow       bool
		argon       bool
		failPersist bool
		password    string
		wantCall    bool
	}{
		{"bcrypt, flag on", true, false, false, validPassword, true},
		{"already argon2id", true, true, false, validPassword, false},
		{"flag off", false, false, false, validPassword, false},
		{"wrong password", true, false, false, "wrong-password-entirely", false},
		{"persist fails", true, false, true, validPassword, false},
	}
	for _, flow := range []string{"signin", "stepup"} {
		for _, tc := range tests {
			t.Run(flow+"/"+tc.name, func(t *testing.T) {
				calls := make(chan legacyCall, 4)
				a, u := legacyCallbackAuth(t, tc.allow, tc.argon, tc.failPersist, func(id, h string) { calls <- legacyCall{id, h} })
				if flow == "signin" {
					_, _, err := testutil.SigninWithPasswordForTest(a, ctx, "legacy@h.com", tc.password, "ua", "")
					if tc.allow && tc.password == validPassword && !tc.failPersist || tc.argon {
						if err != nil {
							t.Fatal(err)
						}
					}
				} else {
					_, sess, err := testutil.IssueSessionForTest(a, ctx, u, "ua", "")
					if err != nil {
						t.Fatal(err)
					}
					_, _ = a.StepUp(ctx, &sess, theauth.StepUpInput{Method: theauth.StepUpMethodPassword, Password: tc.password})
				}
				if tc.wantCall {
					select {
					case c := <-calls:
						if c.userID != u.ID.String() || !strings.HasPrefix(c.hash, "$argon2id$") {
							t.Fatalf("bad callback args: %q %.12s", c.userID, c.hash)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("callback not invoked")
					}
				}
				select {
				case c := <-calls:
					t.Fatalf("unexpected extra callback: %+v", c)
				case <-time.After(150 * time.Millisecond):
				}
			})
		}
	}
}

func TestOnLegacyHashAcceptedOffRequestGoroutine(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	done := make(chan struct{})
	a, _ := legacyCallbackAuth(t, true, false, false, func(string, string) {
		defer close(done)
		<-release
	})
	finished := make(chan error, 1)
	go func() {
		_, _, err := testutil.SigninWithPasswordForTest(a, ctx, "legacy@h.com", validPassword, "ua", "")
		finished <- err
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("signin blocked on the callback")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("callback never ran")
	}
}

func TestOnLegacyHashAcceptedPanicDoesNotBreakLogin(t *testing.T) {
	ctx := context.Background()
	ran := make(chan struct{})
	a, _ := legacyCallbackAuth(t, true, false, false, func(string, string) {
		defer close(ran)
		panic("host bug")
	})
	if _, _, err := testutil.SigninWithPasswordForTest(a, ctx, "legacy@h.com", validPassword, "ua", ""); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("callback never ran")
	}
	time.Sleep(50 * time.Millisecond)
	if _, _, err := testutil.SigninWithPasswordForTest(a, ctx, "legacy@h.com", validPassword, "ua", ""); err != nil {
		t.Fatalf("second login after panic: %v", err)
	}
}
