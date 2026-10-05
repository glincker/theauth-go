// Package testutil adapts the root test hooks to typed helpers for the
// black-box integration tests.
package testutil

import (
	"context"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/testhooks"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

func ValidateEmailForTest(raw string) (string, error) { return testhooks.ValidateEmail(raw) }

func IssueSessionForTest(a *theauth.TheAuth, ctx context.Context, user theauth.User, ua, ip string) (string, theauth.Session, error) {
	return testhooks.IssueSession(a, ctx, user, ua, ip)
}

func ValidateSessionForTest(a *theauth.TheAuth, ctx context.Context, token string) (*theauth.Session, *theauth.User, error) {
	return testhooks.ValidateSession(a, ctx, token)
}

func RequestMagicLinkForTest(a *theauth.TheAuth, ctx context.Context, email string) (string, error) {
	return testhooks.RequestMagicLink(a, ctx, email)
}

func ConsumeMagicLinkForTest(a *theauth.TheAuth, ctx context.Context, token string) (string, *theauth.User, error) {
	return testhooks.ConsumeMagicLink(a, ctx, token)
}

func SetBaseURLForTest(a *theauth.TheAuth, url string) { testhooks.SetBaseURL(a, url) }

func SignupWithPasswordForTest(a *theauth.TheAuth, ctx context.Context, email, password string) (*theauth.User, string, error) {
	return testhooks.SignupWithPassword(a, ctx, email, password)
}

func SigninWithPasswordForTest(a *theauth.TheAuth, ctx context.Context, email, password, ua, ip string) (string, *theauth.User, error) {
	return testhooks.SigninWithPassword(a, ctx, email, password, ua, ip)
}

func RequestPasswordResetForTest(a *theauth.TheAuth, ctx context.Context, email string) (string, error) {
	return testhooks.RequestPasswordReset(a, ctx, email)
}

func ResetPasswordForTest(a *theauth.TheAuth, ctx context.Context, token, newPassword string) error {
	return testhooks.ResetPassword(a, ctx, token, newPassword)
}

// KeyedLimiterForTest wraps the root keyed limiter for GC tests.
type KeyedLimiterForTest struct{ inner testhooks.Limiter }

func NewKeyedLimiterForTest(perMinute int, evictAfter, tickerEvery time.Duration) *KeyedLimiterForTest {
	return &KeyedLimiterForTest{inner: testhooks.NewKeyedLimiter(perMinute, evictAfter, tickerEvery)}
}

func (k *KeyedLimiterForTest) Allow(key string) bool { return k.inner.Allow(key) }
func (k *KeyedLimiterForTest) Stop()                 { k.inner.Stop() }
func (k *KeyedLimiterForTest) EntryCount() int       { return k.inner.EntryCount() }

func IssuePending2FAForTest(a *theauth.TheAuth, ctx context.Context, userID theauth.ULID, ua, ip string) (string, theauth.Session, error) {
	return a.IssuePending2FA(ctx, userID, ua, ip)
}

func BeginTOTPEnrollmentForTest(a *theauth.TheAuth, ctx context.Context, userID theauth.ULID, accountName string) (theauth.EnrollTOTPResult, error) {
	return a.BeginTOTPEnrollment(ctx, userID, accountName)
}

func FinishTOTPEnrollmentForTest(a *theauth.TheAuth, ctx context.Context, userID theauth.ULID, enrollmentID, code string) ([]string, error) {
	return a.FinishTOTPEnrollment(ctx, userID, enrollmentID, code)
}

func VerifyTOTPForTest(a *theauth.TheAuth, ctx context.Context, pendingToken, code string) (string, theauth.Session, error) {
	return a.VerifyTOTP(ctx, pendingToken, code)
}

func ConsumeRecoveryCodeForTest(a *theauth.TheAuth, ctx context.Context, pendingToken, code string) (string, theauth.Session, error) {
	return a.ConsumeRecoveryCode(ctx, pendingToken, code)
}

func LinkOAuthForTest(a *theauth.TheAuth, ctx context.Context, sessionToken, provider, providerUserID string) error {
	return testhooks.LinkOAuth(a, ctx, sessionToken, provider, providerUserID)
}

func LinkPasswordForTest(a *theauth.TheAuth, ctx context.Context, sessionToken, password string) error {
	return testhooks.LinkPassword(a, ctx, sessionToken, password)
}

func MergeAccountsForTest(a *theauth.TheAuth, ctx context.Context, sessionToken string, secondaryID theauth.ULID) error {
	return testhooks.MergeAccounts(a, ctx, sessionToken, secondaryID)
}

func UnlinkOAuthForTest(a *theauth.TheAuth, ctx context.Context, sessionToken, provider string) error {
	return testhooks.UnlinkOAuth(a, ctx, sessionToken, provider)
}

func NewRawTokenForTest() (string, error) { return crypto.NewToken() }

func HashTokenForTest(token string) []byte { return crypto.HashToken(token) }

// SignupWithPasswordForTestStore creates a bare user straight in the store.
func SignupWithPasswordForTestStore(s interface {
	CreateUser(ctx context.Context, u theauth.User) (theauth.User, error)
}, email string) (*theauth.User, string, error) {
	now := time.Now()
	u, err := s.CreateUser(context.Background(), theauth.User{ID: ulid.New(), Email: email, CreatedAt: now, UpdatedAt: now})
	return &u, "", err
}

func OAuthCodeChallengeForTest(verifier string) string { return crypto.CodeChallenge(verifier) }

func SetAPITokenClockForTest(a *theauth.TheAuth, now func() time.Time) {
	testhooks.SetAPITokenClock(a, now)
}
