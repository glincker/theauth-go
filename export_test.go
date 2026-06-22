package theauth

import (
	"context"
	"time"
)

// ValidateEmailForTest exposes the unexported validateEmail helper for
// fuzzing. Returns the normalized address on success, an error otherwise.
func ValidateEmailForTest(raw string) (string, error) {
	return validateEmail(raw)
}

// IssueSessionForTest exposes the unexported issueSession for external tests.
func IssueSessionForTest(a *TheAuth, ctx context.Context, user User, userAgent, ip string) (string, Session, error) {
	return a.issueSession(ctx, user, userAgent, ip)
}

// ValidateSessionForTest exposes the unexported validateSession for external tests.
func ValidateSessionForTest(a *TheAuth, ctx context.Context, token string) (*Session, *User, error) {
	return a.validateSession(ctx, token)
}

// RequestMagicLinkForTest exposes the unexported requestMagicLinkForTest for external tests.
func RequestMagicLinkForTest(a *TheAuth, ctx context.Context, email string) (string, error) {
	return a.requestMagicLinkForTest(ctx, email)
}

// ConsumeMagicLinkForTest exposes the unexported consumeMagicLink for external tests.
func ConsumeMagicLinkForTest(a *TheAuth, ctx context.Context, token string) (string, *User, error) {
	return a.consumeMagicLink(ctx, token)
}

// SetBaseURLForTest exposes the unexported baseURL field for tests that
// need to point the TheAuth instance at an httptest.Server URL.
func SetBaseURLForTest(a *TheAuth, url string) {
	a.baseURL = url
}

// SignupWithPasswordForTest exposes the unexported signupWithPassword for external tests.
func SignupWithPasswordForTest(a *TheAuth, ctx context.Context, email, password string) (*User, string, error) {
	return a.signupWithPassword(ctx, email, password)
}

// SigninWithPasswordForTest exposes the unexported signinWithPassword for
// external tests. v0.5 added the SigninStep return value; older tests pass
// nil for the step pointer.
func SigninWithPasswordForTest(a *TheAuth, ctx context.Context, email, password, ua, ip string) (string, *User, error) {
	tok, u, _, err := a.signinWithPassword(ctx, email, password, ua, ip)
	return tok, u, err
}

// RequestPasswordResetForTest exposes the unexported requestPasswordResetForTest for external tests.
func RequestPasswordResetForTest(a *TheAuth, ctx context.Context, email string) (string, error) {
	return a.requestPasswordResetForTest(ctx, email)
}

// ResetPasswordForTest exposes the unexported resetPassword for external tests.
func ResetPasswordForTest(a *TheAuth, ctx context.Context, token, newPassword string) error {
	return a.resetPassword(ctx, token, newPassword)
}

// KeyedLimiterForTest is an opaque handle exposing the internal keyedLimiter
// for direct testing of the GC + Allow loop without going through HTTP.
type KeyedLimiterForTest struct {
	inner *keyedLimiter
}

// NewKeyedLimiterForTest wires up a keyedLimiter with a tighter GC tick than
// production, so tests can observe eviction quickly.
func NewKeyedLimiterForTest(perMinute int, evictAfter, tickerEvery time.Duration) *KeyedLimiterForTest {
	return &KeyedLimiterForTest{inner: newKeyedLimiterWith(perMinute, evictAfter, tickerEvery)}
}

// Allow forwards to the inner limiter.
func (k *KeyedLimiterForTest) Allow(key string) bool { return k.inner.Allow(key) }

// Stop forwards to the inner limiter.
func (k *KeyedLimiterForTest) Stop() { k.inner.Stop() }

// EntryCount returns the live key count for verifying GC behavior.
func (k *KeyedLimiterForTest) EntryCount() int {
	k.inner.mu.RLock()
	defer k.inner.mu.RUnlock()
	return len(k.inner.limits)
}

// IssuePending2FAForTest exposes the unexported IssuePending2FA for tests.
func IssuePending2FAForTest(a *TheAuth, ctx context.Context, userID ULID, ua, ip string) (string, Session, error) {
	return a.IssuePending2FA(ctx, userID, ua, ip)
}

// BeginTOTPEnrollmentForTest exposes BeginTOTPEnrollment for tests.
func BeginTOTPEnrollmentForTest(a *TheAuth, ctx context.Context, userID ULID, accountName string) (EnrollTOTPResult, error) {
	return a.BeginTOTPEnrollment(ctx, userID, accountName)
}

// FinishTOTPEnrollmentForTest exposes FinishTOTPEnrollment for tests.
func FinishTOTPEnrollmentForTest(a *TheAuth, ctx context.Context, userID ULID, enrollmentID, code string) ([]string, error) {
	return a.FinishTOTPEnrollment(ctx, userID, enrollmentID, code)
}

// VerifyTOTPForTest exposes VerifyTOTP for tests.
func VerifyTOTPForTest(a *TheAuth, ctx context.Context, pendingToken, code string) (string, Session, error) {
	return a.VerifyTOTP(ctx, pendingToken, code)
}

// ConsumeRecoveryCodeForTest exposes ConsumeRecoveryCode for tests.
func ConsumeRecoveryCodeForTest(a *TheAuth, ctx context.Context, pendingToken, code string) (string, Session, error) {
	return a.ConsumeRecoveryCode(ctx, pendingToken, code)
}
