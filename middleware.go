package theauth

import (
	"context"
	"log/slog"
	"net/http"
)

// Authn looks for a session cookie, validates it, and adds the user + session
// to the request context. Does NOT reject anonymous requests. Pair with
// RequireAuth (full) or RequirePendingOrFull (TOTP verify routes only).
func (a *TheAuth) Authn() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(a.cookieName)
			if err != nil || cookie.Value == "" {
				// No cookie present, silent anonymous request.
				next.ServeHTTP(w, r)
				return
			}
			sess, user, err := a.validateSession(r.Context(), cookie.Value)
			if err != nil {
				// Cookie present but validation failed: log so DB outages
				// don't masquerade as "user is anonymous". Token value is
				// never logged.
				slog.Warn("theauth: session validation failed", "err", err.Error())
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), userKey, user)
			ctx = context.WithValue(ctx, sessionKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuth runs Authn, then rejects requests that don't have a FULL
// session. Pending_2fa sessions are treated as unauthorized here. The two
// TOTP verify routes opt in to RequirePendingOrFull instead.
func (a *TheAuth) RequireAuth() func(http.Handler) http.Handler {
	authn := a.Authn()
	return func(next http.Handler) http.Handler {
		return authn(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := SessionFromContext(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			// AuthLevel is "" on pre-v0.5 rows; treat as full for back compat.
			if sess.AuthLevel != "" && sess.AuthLevel != AuthLevelFull {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// RequirePendingOrFull (v0.5) accepts both pending_2fa and full sessions.
// Used exclusively by /auth/totp/verify and /auth/totp/recovery so a user
// mid-step-up can complete the second factor.
func (a *TheAuth) RequirePendingOrFull() func(http.Handler) http.Handler {
	authn := a.Authn()
	return func(next http.Handler) http.Handler {
		return authn(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := SessionFromContext(r.Context()); !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}
