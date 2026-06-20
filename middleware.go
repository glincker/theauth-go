package theauth

import (
	"context"
	"net/http"
)

// Authn looks for a session cookie, validates it, and adds the user + session
// to the request context. Does NOT reject anonymous requests — pair with RequireAuth.
func (a *TheAuth) Authn() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(a.cookieName)
			if err != nil || cookie.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			sess, user, err := a.validateSession(r.Context(), cookie.Value)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), userKey, user)
			ctx = context.WithValue(ctx, sessionKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuth runs Authn, then rejects requests that don't have a session.
func (a *TheAuth) RequireAuth() func(http.Handler) http.Handler {
	authn := a.Authn()
	return func(next http.Handler) http.Handler {
		return authn(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := UserFromContext(r.Context()); !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}
