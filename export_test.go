package theauth

import "context"

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

// SigninWithPasswordForTest exposes the unexported signinWithPassword for external tests.
func SigninWithPasswordForTest(a *TheAuth, ctx context.Context, email, password, ua, ip string) (string, *User, error) {
	return a.signinWithPassword(ctx, email, password, ua, ip)
}

// RequestPasswordResetForTest exposes the unexported requestPasswordResetForTest for external tests.
func RequestPasswordResetForTest(a *TheAuth, ctx context.Context, email string) (string, error) {
	return a.requestPasswordResetForTest(ctx, email)
}

// ResetPasswordForTest exposes the unexported resetPassword for external tests.
func ResetPasswordForTest(a *TheAuth, ctx context.Context, token, newPassword string) error {
	return a.resetPassword(ctx, token, newPassword)
}
