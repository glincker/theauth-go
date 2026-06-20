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
