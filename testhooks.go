package theauth

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/identitylink"
	"github.com/glincker/theauth-go/v2/internal/testhooks"
)

type keyedLimiterHandle struct{ inner *keyedLimiter }

func (k keyedLimiterHandle) Allow(key string) bool { return k.inner.Allow(key) }
func (k keyedLimiterHandle) Stop()                 { k.inner.Stop() }
func (k keyedLimiterHandle) EntryCount() int {
	k.inner.mu.RLock()
	defer k.inner.mu.RUnlock()
	return len(k.inner.limits)
}

func init() {
	testhooks.ValidateEmail = validateEmail
	testhooks.IssueSession = func(a any, ctx context.Context, u User, ua, ip string) (string, Session, error) {
		return a.(*TheAuth).issueSession(ctx, u, ua, ip)
	}
	testhooks.ValidateSession = func(a any, ctx context.Context, token string) (*Session, *User, error) {
		return a.(*TheAuth).validateSession(ctx, token)
	}
	testhooks.RequestMagicLink = func(a any, ctx context.Context, email string) (string, error) {
		return a.(*TheAuth).requestMagicLinkForTest(ctx, email)
	}
	testhooks.ConsumeMagicLink = func(a any, ctx context.Context, token string) (string, *User, error) {
		return a.(*TheAuth).consumeMagicLink(ctx, token)
	}
	testhooks.SetBaseURL = func(a any, url string) { a.(*TheAuth).baseURL = url }
	testhooks.SignupWithPassword = func(a any, ctx context.Context, email, pw string) (*User, string, error) {
		return a.(*TheAuth).signupWithPassword(ctx, email, pw)
	}
	testhooks.SigninWithPassword = func(a any, ctx context.Context, email, pw, ua, ip string) (string, *User, error) {
		tok, u, _, err := a.(*TheAuth).signinWithPassword(ctx, email, pw, ua, ip)
		return tok, u, err
	}
	testhooks.RequestPasswordReset = func(a any, ctx context.Context, email string) (string, error) {
		return a.(*TheAuth).requestPasswordResetForTest(ctx, email)
	}
	testhooks.ResetPassword = func(a any, ctx context.Context, token, pw string) error {
		return a.(*TheAuth).resetPassword(ctx, token, pw)
	}
	testhooks.NewKeyedLimiter = func(perMinute int, evictAfter, tick time.Duration) testhooks.Limiter {
		return keyedLimiterHandle{newKeyedLimiterWith(perMinute, evictAfter, tick)}
	}
	testhooks.LinkOAuth = func(a any, ctx context.Context, sessionToken, provider, pid string) error {
		return a.(*TheAuth).identityLinkSvc.LinkOAuthToCurrentUser(ctx, sessionToken, provider, pid, nil, nil, nil, "")
	}
	testhooks.LinkPassword = func(a any, ctx context.Context, sessionToken, pw string) error {
		return a.(*TheAuth).identityLinkSvc.LinkPasswordToCurrentUser(ctx, sessionToken, pw)
	}
	testhooks.MergeAccounts = func(a any, ctx context.Context, sessionToken string, secondary ULID) error {
		return a.(*TheAuth).identityLinkSvc.MergeAccounts(ctx, sessionToken, secondary, identitylink.MergeInput{})
	}
	testhooks.UnlinkOAuth = func(a any, ctx context.Context, sessionToken, provider string) error {
		return a.(*TheAuth).identityLinkSvc.UnlinkOAuthProvider(ctx, sessionToken, provider)
	}
	testhooks.SetAPITokenClock = func(a any, now func() time.Time) { a.(*TheAuth).apiTokens.now = now }
}
