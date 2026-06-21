package theauth

import (
	"context"
)

// Session issue / validate forwarders. PR A architecture reorg (2026-06)
// moved the implementations to internal/session; the unexported
// issueSession / validateSession entry points kept their exact signatures
// so callers in this package (service_oauth, service_password, service_saml,
// service_totp, service_webauthn, middleware) continue to compile unchanged
// and the export_test.go shims (IssueSessionForTest / ValidateSessionForTest)
// keep working.

// issueSession mints a fresh opaque token, stores its sha256 hash with a
// new Session row, and returns the raw token. The raw token is what the
// caller puts in a cookie / sends to the user; the hash is what's persisted.
func (a *TheAuth) issueSession(ctx context.Context, user User, userAgent, ip string) (token string, sess Session, err error) {
	return a.sessionSvc.Issue(ctx, user, userAgent, ip)
}

// validateSession looks up a session by the hash of the supplied token,
// verifies it is not expired or revoked, and returns the session and its
// user. Returns ErrInvalidToken for missing/unknown tokens and
// ErrSessionExpired for expired or revoked sessions.
func (a *TheAuth) validateSession(ctx context.Context, token string) (*Session, *User, error) {
	return a.sessionSvc.Validate(ctx, token)
}
