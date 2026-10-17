// Package theauthfiber adapts theauth-go middleware and routes to Fiber v2 through Fiber's net/http adaptor.
// Responses from Mount and theauth middleware are fully buffered, so SSE and long polling need
// your own Fiber handlers; put only Authn, RequireAuth and RequireAbility in front of them.
package theauthfiber

import (
	"context"
	"net/http"
	"strings"

	"github.com/glincker/theauth-go/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
)

// Authn resolves the session cookie and attaches the user and session. It
// never rejects: anonymous requests continue with no user.
func Authn(a *theauth.TheAuth) fiber.Handler { return wrap(a.Authn()) }

// RequireAuth rejects requests without a fully authenticated session
// (401 through the configured error responder). It implies Authn.
func RequireAuth(a *theauth.TheAuth) fiber.Handler { return wrap(a.RequireAuth()) }

// RequireAbility accepts a full session or an API bearer token holding
// ability. Needs Config.APITokens.
func RequireAbility(a *theauth.TheAuth, ability string) fiber.Handler {
	return wrap(a.RequireAbility(ability))
}

// User returns the authenticated user set by Authn, RequireAuth or
// RequireAbility.
func User(c *fiber.Ctx) (*theauth.User, bool) { return theauth.UserFromContext(ctxOf(c)) }

// Session returns the session set by Authn or RequireAuth.
func Session(c *fiber.Ctx) (*theauth.Session, bool) { return theauth.SessionFromContext(ctxOf(c)) }

// Principal returns the API token or session principal set by RequireAbility.
func Principal(c *fiber.Ctx) (*theauth.Principal, bool) {
	return theauth.PrincipalFromContext(ctxOf(c))
}

// Mount serves every theauth route (auth, oauth and well-known) under prefix, e.g.
// Mount(a, app, "/api") serves /api/auth/signin. The routes keep Config.PathPrefix below prefix.
// An empty prefix mounts at the router root.
func Mount(a *theauth.TheAuth, r fiber.Router, prefix string) {
	prefix = strings.TrimRight(prefix, "/")
	h := http.Handler(a.Handler())
	if prefix != "" {
		r.All(prefix+"/*", adaptor.HTTPHandler(http.StripPrefix(prefix, h)))
		return
	}
	for _, root := range []string{"/auth", "/oauth", "/.well-known"} {
		r.All(root+"/*", adaptor.HTTPHandler(h))
	}
}

func ctxOf(c *fiber.Ctx) context.Context { return c.UserContext() }

// wrap turns a net/http middleware into a fiber handler, carrying the attached user and session
// into the Fiber context.
func wrap(mw func(http.Handler) http.Handler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var next context.Context
		h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			next = r.Context()
		}))
		if err := adaptor.HTTPHandler(h)(c); err != nil {
			return err
		}
		if next == nil {
			return nil
		}
		// Reset the buffered writer's placeholder 200 so the downstream handler owns the response.
		c.Response().ResetBody()
		c.SetUserContext(next)
		return c.Next()
	}
}
