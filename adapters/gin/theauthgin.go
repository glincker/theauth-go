// Package theauthgin adapts theauth-go middleware and routes to Gin.
//
// It wraps the net/http middleware of a *theauth.TheAuth as native
// gin.HandlerFunc values and exposes the authenticated user, session and API
// token principal through gin accessors. Error responses are written by
// theauth itself, so Config.ErrorResponder (when set) shapes them exactly as
// it does under net/http; the adapter never writes its own error bodies.
package theauthgin

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/glincker/theauth-go/v2"
)

// Authn resolves the session cookie and attaches the user and session. It
// never rejects: anonymous requests continue with no user.
func Authn(a *theauth.TheAuth) gin.HandlerFunc { return wrap(a.Authn()) }

// RequireAuth rejects requests without a fully authenticated session
// (401 through the configured error responder). It implies Authn.
func RequireAuth(a *theauth.TheAuth) gin.HandlerFunc { return wrap(a.RequireAuth()) }

// RequireAbility accepts a full session or an API bearer token holding
// ability. Needs Config.APITokens.
func RequireAbility(a *theauth.TheAuth, ability string) gin.HandlerFunc {
	return wrap(a.RequireAbility(ability))
}

// User returns the authenticated user set by Authn, RequireAuth or
// RequireAbility.
func User(c *gin.Context) (*theauth.User, bool) {
	return theauth.UserFromContext(c.Request.Context())
}

// Session returns the session set by Authn or RequireAuth.
func Session(c *gin.Context) (*theauth.Session, bool) {
	return theauth.SessionFromContext(c.Request.Context())
}

// Principal returns the API token or session principal set by RequireAbility.
func Principal(c *gin.Context) (*theauth.Principal, bool) {
	return theauth.PrincipalFromContext(c.Request.Context())
}

// Mount serves every theauth route (auth, oauth and well-known) under prefix,
// for example Mount(a, r, "/api") serves /api/auth/signin. The routes keep
// Config.PathPrefix below prefix. An empty prefix mounts /auth, /oauth and
// /.well-known at the router root.
func Mount(a *theauth.TheAuth, r gin.IRoutes, prefix string) {
	prefix = strings.TrimRight(prefix, "/")
	h := http.Handler(a.Handler())
	if prefix != "" {
		r.Any(prefix+"/*theauth", gin.WrapH(http.StripPrefix(prefix, h)))
		return
	}
	for _, root := range []string{"/auth", "/oauth", "/.well-known"} {
		r.Any(root+"/*theauth", gin.WrapH(h))
	}
}

// wrap turns a net/http middleware into a gin handler. The request replaced
// by the middleware (carrying the user and session in its context) is
// installed before the rest of the chain runs; a middleware that wrote a
// response aborts the chain.
func wrap(mw func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		passed := false
		mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			passed = true
			c.Request = r
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)
		if !passed {
			c.Abort()
		}
	}
}
