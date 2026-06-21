package theauth_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
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
