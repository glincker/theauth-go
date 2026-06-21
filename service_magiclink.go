package theauth

import "context"

// Magic-link request / consume forwarders. PR A architecture reorg
// (2026-06) moved the implementations to internal/magiclink; the
// unexported requestMagicLink / requestMagicLinkForTest / consumeMagicLink
// entry points kept their exact signatures so existing call sites
// (service_password, handlers, export_test.go) continue to compile.

// requestMagicLink mints a magic-link token, persists its hash, and emails
// the raw token to the user as a click-through verification link.
// Production code calls this; the raw token only ever appears in the inbox.
func (a *TheAuth) requestMagicLink(ctx context.Context, emailAddr string) error {
	return a.magicSvc.Request(ctx, emailAddr)
}

// requestMagicLinkForTest is the same as requestMagicLink but returns the
// raw token so tests can drive a consume flow without scraping email.
func (a *TheAuth) requestMagicLinkForTest(ctx context.Context, emailAddr string) (string, error) {
	return a.magicSvc.RequestForTest(ctx, emailAddr)
}

// consumeMagicLink atomically marks a magic-link as used, finds-or-creates
// the corresponding user, marks their email verified, and issues a fresh
// session. Returns ErrInvalidToken for unknown tokens and
// ErrMagicLinkExpired when the link's TTL has elapsed.
func (a *TheAuth) consumeMagicLink(ctx context.Context, token string) (sessionToken string, user *User, err error) {
	return a.magicSvc.Consume(ctx, token)
}
