package integration

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/integration/internal/testutil"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/pquerna/otp/totp"
)

const authMethodsPW = "twelve-chars-min-pw"

type authMethodsFixture struct {
	a     *theauth.TheAuth
	store *memory.Store
}

func newAuthMethodsFixture(t *testing.T) authMethodsFixture {
	return newAuthMethodsFixtureWith(t, nil)
}

func newAuthMethodsFixtureWith(t *testing.T, mutate func(*theauth.Config)) authMethodsFixture {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	cfg := theauth.Config{
		Storage: store, BaseURL: "http://localhost", EncryptionKey: key,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
		TOTP: &theauth.TOTPConfig{Issuer: "AuthMethods"},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := theauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return authMethodsFixture{a: a, store: store}
}

func (f authMethodsFixture) session(t *testing.T, token string) *theauth.Session {
	t.Helper()
	s, _, err := testutil.ValidateSessionForTest(f.a, context.Background(), token)
	if err != nil {
		t.Fatalf("validate session: %v", err)
	}
	return s
}

func wantMethods(t *testing.T, s *theauth.Session, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(s.AuthMethods, want) {
		t.Fatalf("AuthMethods = %v, want %v", s.AuthMethods, want)
	}
	if s.AuthTime.IsZero() {
		t.Fatal("AuthTime is zero on a session with a record")
	}
}

// enrollTOTP signs a user up with a password and enrolls TOTP, returning the
// user, the signup session token and the TOTP secret.
func (f authMethodsFixture) enrollTOTP(t *testing.T, email string) (*theauth.User, string, string, []string) {
	t.Helper()
	ctx := context.Background()
	u, tok, err := testutil.SignupWithPasswordForTest(f.a, ctx, email, authMethodsPW)
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	enroll, err := testutil.BeginTOTPEnrollmentForTest(f.a, ctx, u.ID, email)
	if err != nil {
		t.Fatalf("enroll begin: %v", err)
	}
	code, _ := totp.GenerateCode(enroll.Secret, time.Now())
	recovery, err := testutil.FinishTOTPEnrollmentForTest(f.a, ctx, u.ID, enroll.EnrollmentID, code)
	if err != nil {
		t.Fatalf("enroll finish: %v", err)
	}
	return u, tok, enroll.Secret, recovery
}

func TestSignInMethodsRecordAMR(t *testing.T) {
	f := newAuthMethodsFixture(t)
	ctx := context.Background()
	before := time.Now().Add(-time.Second)

	t.Run("password signup", func(t *testing.T) {
		_, tok, err := testutil.SignupWithPasswordForTest(f.a, ctx, "signup@h.com", authMethodsPW)
		if err != nil {
			t.Fatal(err)
		}
		s := f.session(t, tok)
		wantMethods(t, s, "pwd")
		if s.AuthTime.Before(before) {
			t.Errorf("AuthTime %v predates sign-in", s.AuthTime)
		}
	})
	t.Run("password signin", func(t *testing.T) {
		if _, _, err := testutil.SignupWithPasswordForTest(f.a, ctx, "signin@h.com", authMethodsPW); err != nil {
			t.Fatal(err)
		}
		tok, _, err := testutil.SigninWithPasswordForTest(f.a, ctx, "signin@h.com", authMethodsPW, "ua", "1.2.3.4")
		if err != nil {
			t.Fatal(err)
		}
		wantMethods(t, f.session(t, tok), "pwd")
	})
	t.Run("magic link", func(t *testing.T) {
		raw, err := testutil.RequestMagicLinkForTest(f.a, ctx, "magic@h.com")
		if err != nil {
			t.Fatal(err)
		}
		tok, _, err := testutil.ConsumeMagicLinkForTest(f.a, ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		wantMethods(t, f.session(t, tok), "email")
	})
	t.Run("pending 2fa after password", func(t *testing.T) {
		u, _, _, _ := f.enrollTOTP(t, "pending@h.com")
		tok, _, err := testutil.SigninWithPasswordForTest(f.a, ctx, "pending@h.com", authMethodsPW, "ua", "1.2.3.4")
		if err != nil {
			t.Fatal(err)
		}
		pend, err := f.store.SessionByTokenHash(ctx, hashToken(tok))
		if err != nil {
			t.Fatal(err)
		}
		if pend.AuthLevel != theauth.AuthLevelPending2FA || !reflect.DeepEqual(pend.AuthMethods, []string{"pwd"}) {
			t.Fatalf("pending session = %s %v for %s, want pending_2fa [pwd]", pend.AuthLevel, pend.AuthMethods, u.ID)
		}
	})
}

func hashToken(tok string) []byte { return testutil.HashTokenForTest(tok) }

func TestSecondFactorAppendsAndBumpsAuthTime(t *testing.T) {
	f := newAuthMethodsFixture(t)
	ctx := context.Background()
	_, _, secret, recovery := f.enrollTOTP(t, "mfa@h.com")

	signin := func() (string, *theauth.Session) {
		tok, _, err := testutil.SigninWithPasswordForTest(f.a, ctx, "mfa@h.com", authMethodsPW, "ua", "1.2.3.4")
		if err != nil {
			t.Fatal(err)
		}
		s, err := f.store.SessionByTokenHash(ctx, hashToken(tok))
		if err != nil {
			t.Fatal(err)
		}
		return tok, s
	}

	t.Run("totp", func(t *testing.T) {
		tok, pend := signin()
		time.Sleep(20 * time.Millisecond)
		code, _ := totp.GenerateCode(secret, time.Now())
		_, upgraded, err := testutil.VerifyTOTPForTest(f.a, ctx, tok, code)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		wantMethods(t, &upgraded, "pwd", "otp", "mfa")
		if !upgraded.AuthTime.After(pend.AuthTime) {
			t.Errorf("AuthTime %v not after pending %v", upgraded.AuthTime, pend.AuthTime)
		}
		stored := f.session(t, tok)
		wantMethods(t, stored, "pwd", "otp", "mfa")
		if !stored.HasMethod("otp") || !stored.HasAllMethods("pwd", "mfa") || stored.HasMethod("hwk") || stored.HasAnyMethod("hwk", "swk") {
			t.Errorf("Has* helpers disagree with %v", stored.AuthMethods)
		}
	})
	t.Run("recovery code", func(t *testing.T) {
		tok, _ := signin()
		_, upgraded, err := testutil.ConsumeRecoveryCodeForTest(f.a, ctx, tok, recovery[0])
		if err != nil {
			t.Fatalf("recovery: %v", err)
		}
		wantMethods(t, &upgraded, "pwd", "otp", "mfa")
		wantMethods(t, f.session(t, tok), "pwd", "otp", "mfa")
	})
}

func TestStepUpAppendsMethodsAndBumpsAuthTime(t *testing.T) {
	f := newAuthMethodsFixture(t)
	ctx := context.Background()
	_, tok, secret, _ := f.enrollTOTP(t, "stepup-am@h.com")
	sess := f.session(t, tok)
	wantMethods(t, sess, "pwd")
	first := sess.AuthTime

	// A password step-up repeats a method already proved: no mfa, later time.
	time.Sleep(20 * time.Millisecond)
	if _, err := f.a.StepUp(ctx, sess, theauth.StepUpInput{Method: theauth.StepUpMethodPassword, Password: authMethodsPW}); err != nil {
		t.Fatalf("password step-up: %v", err)
	}
	wantMethods(t, sess, "pwd")
	if !sess.AuthTime.After(first) {
		t.Errorf("password step-up did not bump AuthTime: %v then %v", first, sess.AuthTime)
	}

	// A TOTP step-up adds a new factor.
	time.Sleep(20 * time.Millisecond)
	code, _ := totp.GenerateCode(secret, time.Now())
	if _, err := f.a.StepUp(ctx, sess, theauth.StepUpInput{Method: theauth.StepUpMethodTOTP, Code: code}); err != nil {
		t.Fatalf("totp step-up: %v", err)
	}
	stored := f.session(t, tok)
	wantMethods(t, stored, "pwd", "otp", "mfa")
	if !stored.AuthTime.After(first) {
		t.Errorf("stored AuthTime %v not after sign-in %v", stored.AuthTime, first)
	}
	if !sess.HasMethod("otp") {
		t.Errorf("StepUp did not update the caller's session: %v", sess.AuthMethods)
	}
}

func TestLegacySessionUnchangedUntilStepUp(t *testing.T) {
	f := newAuthMethodsFixture(t)
	ctx := context.Background()
	u, _, secret, _ := f.enrollTOTP(t, "legacy-am@h.com")
	created := time.Now().Add(-time.Hour)
	if _, err := f.store.CreateSession(ctx, theauth.Session{
		ID: ulid.New(), UserID: u.ID, TokenHash: hashToken("legacy-token"),
		CreatedAt: created, LastSeenAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	legacy := f.session(t, "legacy-token")
	if len(legacy.AuthMethods) != 0 || !legacy.AuthTime.IsZero() || legacy.HasMethod("pwd") {
		t.Fatalf("legacy session = %v %v, want no record", legacy.AuthMethods, legacy.AuthTime)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if _, err := f.a.StepUp(ctx, legacy, theauth.StepUpInput{Method: theauth.StepUpMethodTOTP, Code: code}); err != nil {
		t.Fatalf("step-up: %v", err)
	}
	// Nothing is inferred for a session with no record: only the TOTP that
	// was actually proved is recorded, with no pwd baseline and no mfa.
	got := f.session(t, "legacy-token")
	wantMethods(t, got, "otp")
	if got.HasMethod("mfa") || got.HasMethod("pwd") {
		t.Errorf("legacy step-up inferred methods: %v", got.AuthMethods)
	}
}

func TestRotateSessionKeepsRecord(t *testing.T) {
	f := newAuthMethodsFixture(t)
	ctx := context.Background()
	_, tok, _, _ := f.enrollTOTP(t, "rotate-am@h.com")
	old := f.session(t, tok)
	if err := f.a.RecordSessionAuth(ctx, old, theauth.AMROTP, theauth.AMRMFA); err != nil {
		t.Fatal(err)
	}
	newTok, ns, err := f.a.RotateSession(ctx, *old)
	if err != nil {
		t.Fatal(err)
	}
	wantMethods(t, f.session(t, newTok), "pwd", "otp", "mfa")
	if !ns.AuthTime.Equal(old.AuthTime) {
		t.Errorf("rotated AuthTime %v, want original %v", ns.AuthTime, old.AuthTime)
	}
}

func TestConcurrentRecordSessionAuthLosesNothing(t *testing.T) {
	f := newAuthMethodsFixture(t)
	ctx := context.Background()
	_, tok, _, _ := f.enrollTOTP(t, "race-am@h.com")
	base := f.session(t, tok)
	const n = 24
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := *base
			if err := f.a.RecordSessionAuth(ctx, &s, fmt.Sprintf("m%d", i)); err != nil {
				t.Errorf("record %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	got := f.session(t, tok)
	if len(got.AuthMethods) != n+1 {
		t.Fatalf("AuthMethods has %d entries, want %d: %v", len(got.AuthMethods), n+1, got.AuthMethods)
	}
}

// bareStorage hides every optional capability of the wrapped store, like a
// third party Storage written before SessionAuthStorage existed.
type bareStorage struct{ theauth.Storage }

func TestStorageWithoutCapabilityStillSignsIn(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	a, err := theauth.New(theauth.Config{
		Storage: bareStorage{memory.New()}, BaseURL: "http://localhost", EncryptionKey: key,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	ctx := context.Background()
	_, tok, err := testutil.SignupWithPasswordForTest(a, ctx, "bare@h.com", authMethodsPW)
	if err != nil {
		t.Fatal(err)
	}
	s, _, err := testutil.ValidateSessionForTest(a, ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RecordSessionAuth(ctx, s, theauth.AMROTP); !errors.Is(err, theauth.ErrStorageMissingCapability) {
		t.Errorf("RecordSessionAuth err = %v, want ErrStorageMissingCapability", err)
	}
}

type allowCredentials struct{}

func (allowCredentials) CheckCredential(context.Context, string) error { return nil }

// TestNonInteractiveSessionsNeverSatisfyStrongMethods classifies every way a
// session can come into being without an interactive sign-in and asserts none
// of them carries an AuthTime or a method a passkey or TOTP requirement would
// accept. Device codes, API tokens and OAuth refresh or exchange grants mint
// no browser session at all, so there is no session for them to be confused
// with; the remaining session producing paths are covered here.
func TestNonInteractiveSessionsNeverSatisfyStrongMethods(t *testing.T) {
	f := newAuthMethodsFixtureWith(t, func(c *theauth.Config) {
		c.SessionLinks = &theauth.SessionLinksConfig{CredentialChecker: allowCredentials{}}
	})
	ctx := context.Background()
	u, _, _, _ := f.enrollTOTP(t, "noninteractive@h.com")

	origins := map[string]func(t *testing.T) *theauth.Session{
		"session link": func(t *testing.T) *theauth.Session {
			link, _, err := f.a.MintSessionLink(ctx, theauth.MintSessionLinkInput{UserID: u.ID, CredentialID: "cred-1"})
			if err != nil {
				t.Fatal(err)
			}
			tok, _, err := f.a.ConsumeSessionLink(ctx, link, "ua", "1.2.3.4")
			if err != nil {
				t.Fatal(err)
			}
			return f.session(t, tok)
		},
		"session link without credential": func(t *testing.T) *theauth.Session {
			link, _, err := f.a.MintSessionLink(ctx, theauth.MintSessionLinkInput{UserID: u.ID})
			if err != nil {
				t.Fatal(err)
			}
			tok, _, err := f.a.ConsumeSessionLink(ctx, link, "ua", "1.2.3.4")
			if err != nil {
				t.Fatal(err)
			}
			return f.session(t, tok)
		},
		"programmatic IssueSessionByUserID": func(t *testing.T) *theauth.Session {
			tok, err := f.a.IssueSessionByUserID(ctx, u.ID, "ua", "1.2.3.4")
			if err != nil {
				t.Fatal(err)
			}
			return f.session(t, tok)
		},
		"admin or impersonation row written to storage": func(t *testing.T) *theauth.Session {
			if _, err := f.store.CreateSession(ctx, theauth.Session{
				ID: ulid.New(), UserID: u.ID, TokenHash: hashToken("admin-created"),
				CreatedAt: time.Now(), LastSeenAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			}); err != nil {
				t.Fatal(err)
			}
			return f.session(t, "admin-created")
		},
	}
	for name, mk := range origins {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			if len(s.AuthMethods) != 0 || !s.AuthTime.IsZero() {
				t.Fatalf("carries a record: %v %v", s.AuthMethods, s.AuthTime)
			}
			if s.HasAnyMethod(theauth.AMRHardwareKey, theauth.AMRSoftwareKey, theauth.AMROTP, theauth.AMRMFA, theauth.AMRPassword) {
				t.Fatal("satisfies a passkey, TOTP, mfa or password requirement without any step-up")
			}
		})
	}

	// A real TOTP step-up on a password session appends otp and mfa and bumps
	// AuthTime; the same step-up on a session link proves only otp.
	_, pwTok, pwSecret, _ := f.enrollTOTP(t, "contrast-pw@h.com")
	pw := f.session(t, pwTok)
	before := pw.AuthTime
	time.Sleep(20 * time.Millisecond)
	code, _ := totp.GenerateCode(pwSecret, time.Now())
	if _, err := f.a.StepUp(ctx, pw, theauth.StepUpInput{Method: theauth.StepUpMethodTOTP, Code: code}); err != nil {
		t.Fatal(err)
	}
	got := f.session(t, pwTok)
	wantMethods(t, got, "pwd", "otp", "mfa")
	if !got.AuthTime.After(before) {
		t.Errorf("password session AuthTime not bumped: %v then %v", before, got.AuthTime)
	}

	linkUser, _, linkSecret, _ := f.enrollTOTP(t, "contrast-link@h.com")
	link, _, err := f.a.MintSessionLink(ctx, theauth.MintSessionLinkInput{UserID: linkUser.ID})
	if err != nil {
		t.Fatal(err)
	}
	linkTok, _, err := f.a.ConsumeSessionLink(ctx, link, "ua", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	ls := f.session(t, linkTok)
	if ls.HasAnyMethod(theauth.AMROTP, theauth.AMRMFA) {
		t.Fatal("session link satisfied a TOTP requirement before any step-up")
	}
	code, _ = totp.GenerateCode(linkSecret, time.Now())
	if _, err := f.a.StepUp(ctx, ls, theauth.StepUpInput{Method: theauth.StepUpMethodTOTP, Code: code}); err != nil {
		t.Fatal(err)
	}
	after := f.session(t, linkTok)
	wantMethods(t, after, "otp")
	if after.HasMethod("mfa") || after.HasMethod("pwd") {
		t.Errorf("link step-up inferred methods: %v", after.AuthMethods)
	}
}
