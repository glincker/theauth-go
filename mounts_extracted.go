package theauth

import (
	"context"
	"net/http"

	ashandlers "github.com/glincker/theauth-go/internal/as/handlers"
	"github.com/glincker/theauth-go/internal/models"
	oauthhandlers "github.com/glincker/theauth-go/internal/oauth/handlers"
	passwordhandlers "github.com/glincker/theauth-go/internal/password/handlers"
	totphandlers "github.com/glincker/theauth-go/internal/totp/handlers"
	webauthnhandlers "github.com/glincker/theauth-go/internal/webauthn/handlers"
	"github.com/go-chi/chi/v5"
)

// mounts_extracted.go consolidates the five thinnest PR-E / PR-F mount
// forwarders: password, TOTP, WebAuthn, OAuth provider (the
// /auth/providers/* tree), and the OAuth 2.1 authorization server
// (.well-known + /oauth/*). PR G (2026-06-21) merged the previous
// handlers_password.go, handlers_totp.go, handlers_webauthn.go,
// handlers_oauth.go, and handlers_oauth_server.go files here so the root
// package presents one place for the small chi.Router wiring shims that
// instantiate the extracted internal/<flow>/handlers packages. No
// behaviour change; route paths and middleware chains are byte-stable
// with v2.0. Larger mount files that carry substantive service adapters
// (account, admin, admin_agents, organizations, saml, scim) stay in
// their own files.

// oauthServiceAdapter implements internal/oauth/handlers.Service on top
// of the root *TheAuth, exposing only the three methods the extracted
// handler needs. The OAuth service itself still lives in root
// (service_oauth.go); a future PR can extract it into internal/oauth
// like PR D did for password / totp / webauthn / saml.
type oauthServiceAdapter struct{ a *TheAuth }

// HasProvider reports whether the named provider is registered.
func (s oauthServiceAdapter) HasProvider(name string) bool {
	_, ok := s.a.providers[name]
	return ok
}

// Start delegates the /auth/providers/{name}/start flow to
// *TheAuth.startOAuth.
func (s oauthServiceAdapter) Start(ctx context.Context, providerName string) (string, string, error) {
	return s.a.startOAuth(ctx, providerName)
}

// Callback delegates the /auth/providers/{name}/callback flow to
// *TheAuth.callbackOAuth, discarding the *User return (the handler
// only needs the session token).
func (s oauthServiceAdapter) Callback(ctx context.Context, providerName, code, state, ua, ip string) (string, error) {
	tok, _, err := s.a.callbackOAuth(ctx, providerName, code, state, ua, ip)
	return tok, err
}

// mountPasswordHandlers wires /email-password/* subroutes via the
// extracted internal/password/handlers package. PR E architecture
// reorg (2026-06-20) moved the four endpoints to that package; this
// thin coordinator is what the root Mount calls.
func (a *TheAuth) mountPasswordHandlers(r chi.Router, ipLimit, emailLimit func(http.Handler) http.Handler) {
	h := passwordhandlers.New(a.passwordSvc, passwordhandlers.CookieConfig{
		Name:       a.cookieName,
		SecureFlag: a.secureCookie,
		TTL:        a.sessionTTL,
	})
	h.Mount(r, ipLimit, emailLimit)
}

// mountTOTP wires /auth/totp/* under r via the extracted
// internal/totp/handlers package. PR E architecture reorg
// (2026-06-20) moved the five endpoints to that package; the root
// keeps this thin coordinator so handlers.go is the single Mount
// caller.
func (a *TheAuth) mountTOTP(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	h := totphandlers.New(
		a.totpSvc,
		totphandlers.CookieConfig{
			Name:       a.cookieName,
			SecureFlag: a.secureCookie,
			TTL:        a.sessionTTL,
		},
		func(r *http.Request) (*models.User, bool) {
			return UserFromContext(r.Context())
		},
	)
	h.Mount(r, ipLimit, a.RequireAuth(), a.RequirePendingOrFull())
}

// mountWebAuthn wires /auth/webauthn/* under r via the extracted
// internal/webauthn/handlers package. PR E architecture reorg
// (2026-06-20) moved the six endpoints to that package; the root
// keeps this thin coordinator so handlers.go is the single Mount
// caller.
func (a *TheAuth) mountWebAuthn(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	h := webauthnhandlers.New(
		a.webauthnSvc,
		webauthnhandlers.SessionCookieConfig{
			Name:       a.cookieName,
			SecureFlag: a.secureCookie,
			TTL:        a.sessionTTL,
		},
		webauthnhandlers.ChallengeCookieConfig{
			SecureFlag: a.secureCookie,
			TTL:        a.webauthnCfg.ChallengeTTL,
		},
		func(r *http.Request) (*models.User, bool) {
			return UserFromContext(r.Context())
		},
	)
	h.Mount(r, ipLimit, a.RequireAuth())
}

// mountOAuth wires /auth/providers/* under r via the extracted
// internal/oauth/handlers package. PR E architecture reorg
// (2026-06-20) moved the two endpoints to that package; the root keeps
// this thin coordinator so handlers.go is the single Mount caller.
func (a *TheAuth) mountOAuth(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	h := oauthhandlers.New(
		oauthServiceAdapter{a: a},
		oauthhandlers.SessionCookieConfig{
			Name:       a.cookieName,
			SecureFlag: a.secureCookie,
			TTL:        a.sessionTTL,
		},
		a.postLoginRedirect,
	)
	h.Mount(r, ipLimit)
}

// mountAS wires the OAuth 2.1 authorization server routes (.well-known
// + /oauth/*) via the extracted internal/as/handlers package. Only
// called when Config.AuthorizationServer is non-nil (and therefore a.as
// is non-nil). PR F architecture reorg (2026-06-20) moved the AS HTTP
// surface and the scopeSplit helper there.
func (a *TheAuth) mountAS(r chi.Router) {
	if a.as == nil {
		return
	}
	h := ashandlers.New(a.as, userFromRequest, a.dcrRegistrationTokenHashes)
	var registerLimit func(http.Handler) http.Handler
	if cap := a.as.Cfg.RegistrationRateLimitPerMinute; cap > 0 {
		registerLimit = a.RateLimitByIP(cap)
	}
	h.Mount(r, a.Authn(), registerLimit)
}
