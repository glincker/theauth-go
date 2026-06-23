package theauth

import "context"

// service_oauth.go: thin forwarder shim around the extracted
// internal/oauth.Service. PR H (2026-06-22) moved the implementation of
// the OAuth start/callback state machine (oauthStateGCLoop, startOAuth,
// callbackOAuth, findOrCreateOAuthUser) into internal/oauth/service.go.
// Root keeps these unexported methods so that the oauthServiceAdapter in
// mounts_extracted.go (which satisfies the internal/oauth/handlers.Service
// interface) continues to compile without modification. Public API surface
// is byte-stable.

// startOAuth delegates the /auth/providers/{name}/start flow to
// the extracted internal/oauth.Service.
func (a *TheAuth) startOAuth(ctx context.Context, providerName string) (authURL, state string, err error) {
	return a.oauthSvc.Start(ctx, providerName)
}

// callbackOAuth delegates the /auth/providers/{name}/callback flow to
// the extracted internal/oauth.Service.
func (a *TheAuth) callbackOAuth(ctx context.Context, providerName, code, state, userAgent, ip string) (sessionToken string, user *User, err error) {
	return a.oauthSvc.Callback(ctx, providerName, code, state, userAgent, ip)
}
