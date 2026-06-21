package theauth

import (
	"net/http"

	passwordhandlers "github.com/glincker/theauth-go/internal/password/handlers"
	"github.com/go-chi/chi/v5"
)

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
