package theauth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/glincker/theauth-go/v2/internal/httpsec"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
	"github.com/go-chi/chi/v5"
)

// Handler returns a stdlib http.Handler serving every route Mount would
// register, for consumers on net/http's ServeMux without chi. Routes keep
// their configured paths (Config.PathPrefix, default /auth/..., and /oauth/...),
// so no http.StripPrefix is needed when the prefix matches the mount point.
func (a *TheAuth) Handler() http.Handler {
	r := chi.NewRouter()
	a.Mount(r)
	return r
}

// securityMiddleware applies per-request Secure cookie derivation and the
// Origin check ahead of every route Mount registers.
func (a *TheAuth) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.csrfDisabled && !httpsec.OriginAllowed(r, a.baseURL, a.trustedOrigins) {
			writeJSONError(w, http.StatusForbidden, "csrf_origin_rejected", "request origin is not trusted")
			return
		}
		if a.requestIsSecure(r) {
			w = httpsec.NewCookieWriter(w)
		}
		next.ServeHTTP(w, r)
	})
}

// requestIsSecure reports whether cookies set for r must carry Secure.
// The explicit Config.SecureCookie flag wins; otherwise an https BaseURL,
// direct TLS, or X-Forwarded-Proto: https from a trusted proxy qualifies.
func (a *TheAuth) requestIsSecure(r *http.Request) bool {
	if a.secureCookie {
		return true
	}
	if u, err := url.Parse(a.baseURL); err == nil && strings.EqualFold(u.Scheme, "https") {
		return true
	}
	if r.TLS != nil {
		return true
	}
	if len(a.trustedProxies) > 0 && ratelimit.RemoteIsTrusted(ratelimit.RemoteAddrHost(r), a.trustedProxies) {
		return strings.EqualFold(strings.TrimSpace(firstToken(r.Header.Get("X-Forwarded-Proto"))), "https")
	}
	return false
}

func firstToken(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		return v[:i]
	}
	return v
}
