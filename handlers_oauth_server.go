package theauth

import (
	"net/http"

	ashandlers "github.com/glincker/theauth-go/internal/as/handlers"
	"github.com/go-chi/chi/v5"
)

// handlers_oauth_server.go: thin forwarder around the extracted
// internal/as/handlers package. PR F architecture reorg (2026-06-20)
// moved the AS HTTP surface (well-known + /oauth/* endpoints) and the
// scopeSplit helper there. The root entry point keeps the legacy
// mountAS shape so theauth.go's top-level Mount continues to call
// a.mountAS(r) unchanged.

// mountAS wires the AS routes via the extracted handler. Only called
// when Config.AuthorizationServer is non-nil (and therefore a.as is
// non-nil).
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
