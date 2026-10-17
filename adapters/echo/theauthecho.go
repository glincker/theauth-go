// Package theauthecho adapts theauth-go middleware and routes to Echo v4.
// Error responses are written by theauth itself, so Config.ErrorResponder shapes them.
package theauthecho

import (
	"net/http"
	"strings"

	"github.com/glincker/theauth-go/v2"
	"github.com/labstack/echo/v4"
)

// Authn resolves the session cookie and attaches the user and session. It
// never rejects: anonymous requests continue with no user.
func Authn(a *theauth.TheAuth) echo.MiddlewareFunc { return wrap(a.Authn()) }

// RequireAuth rejects requests without a fully authenticated session
// (401 through the configured error responder). It implies Authn.
func RequireAuth(a *theauth.TheAuth) echo.MiddlewareFunc { return wrap(a.RequireAuth()) }

// RequireAbility accepts a full session or an API bearer token holding
// ability. Needs Config.APITokens.
func RequireAbility(a *theauth.TheAuth, ability string) echo.MiddlewareFunc {
	return wrap(a.RequireAbility(ability))
}

// User returns the authenticated user set by Authn, RequireAuth or
// RequireAbility.
func User(c echo.Context) (*theauth.User, bool) {
	return theauth.UserFromContext(c.Request().Context())
}

// Session returns the session set by Authn or RequireAuth.
func Session(c echo.Context) (*theauth.Session, bool) {
	return theauth.SessionFromContext(c.Request().Context())
}

// Principal returns the API token or session principal set by RequireAbility.
func Principal(c echo.Context) (*theauth.Principal, bool) {
	return theauth.PrincipalFromContext(c.Request().Context())
}

// Mount serves every theauth route (auth, oauth and well-known) under prefix, e.g.
// Mount(a, e, "/api") serves /api/auth/signin. The routes keep Config.PathPrefix below prefix.
// An empty prefix mounts at the router root.
func Mount(a *theauth.TheAuth, r interface {
	Any(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) []*echo.Route
}, prefix string) {
	prefix = strings.TrimRight(prefix, "/")
	h := http.Handler(a.Handler())
	if prefix != "" {
		h = http.StripPrefix(prefix, h)
		r.Any(prefix+"/*", echo.WrapHandler(h))
		return
	}
	for _, root := range []string{"/auth", "/oauth", "/.well-known"} {
		r.Any(root+"/*", echo.WrapHandler(h))
	}
}

// wrap turns a net/http middleware into an echo middleware; a response written by it ends the chain.
func wrap(mw func(http.Handler) http.Handler) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var err error
			mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				err = next(c)
			})).ServeHTTP(c.Response(), c.Request())
			return err
		}
	}
}
