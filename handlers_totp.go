package theauth

import (
	"net/http"

	"github.com/glincker/theauth-go/internal/models"
	totphandlers "github.com/glincker/theauth-go/internal/totp/handlers"
	"github.com/go-chi/chi/v5"
)

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
