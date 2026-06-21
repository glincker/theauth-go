package theauth

import (
	"net/http"

	"github.com/glincker/theauth-go/internal/models"
	webauthnhandlers "github.com/glincker/theauth-go/internal/webauthn/handlers"
	"github.com/go-chi/chi/v5"
)

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
