package theauth

import (
	"context"
	"net/http"

	oauthhandlers "github.com/glincker/theauth-go/internal/oauth/handlers"
	"github.com/go-chi/chi/v5"
)

// oauthServiceAdapter implements internal/oauth/handlers.Service on
// top of the root *TheAuth, exposing only the three methods that the
// extracted handler needs. The OAuth service itself still lives in
// root (service_oauth.go); a future PR can extract it into
// internal/oauth like PR D did for password / totp / webauthn / saml.
type oauthServiceAdapter struct{ a *TheAuth }

func (s oauthServiceAdapter) HasProvider(name string) bool {
	_, ok := s.a.providers[name]
	return ok
}

func (s oauthServiceAdapter) Start(ctx context.Context, providerName string) (string, string, error) {
	return s.a.startOAuth(ctx, providerName)
}

func (s oauthServiceAdapter) Callback(ctx context.Context, providerName, code, state, ua, ip string) (string, error) {
	tok, _, err := s.a.callbackOAuth(ctx, providerName, code, state, ua, ip)
	return tok, err
}

// mountOAuth wires /auth/providers/* under r via the extracted
// internal/oauth/handlers package. PR E architecture reorg
// (2026-06-20) moved the two endpoints to that package; the root
// keeps this thin coordinator so handlers.go is the single Mount
// caller.
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
