package httpsec

import (
	"net/http"
	"strings"
)

// HSTSValue is the Strict-Transport-Security value ApplySecurityHeaders sends: one year, subdomains
// included, no preload (preload is an irreversible opt in the operator makes on their own).
const HSTSValue = "max-age=31536000; includeSubDomains"

// ApplySecurityHeaders sets the opt-in response hardening headers on h: X-Content-Type-Options,
// Referrer-Policy (no-referrer, so magic-link and reset tokens in URLs never leak), X-Frame-Options
// and, when secure is true, Strict-Transport-Security. Headers a handler sets later win.
func ApplySecurityHeaders(h http.Header, secure bool) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	if secure {
		h.Set("Strict-Transport-Security", HSTSValue)
	}
}

// SecurityHeadersMiddleware applies ApplySecurityHeaders to every response. isSecure decides per
// request whether HSTS is sent (it must be ignored over plain http).
func SecurityHeadersMiddleware(isSecure func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ApplySecurityHeaders(w.Header(), isSecure != nil && isSecure(r))
			next.ServeHTTP(w, r)
		})
	}
}

// NoStorePath reports whether path is under prefix, the route tree whose session and credential
// responses must never sit in a shared or browser cache.
func NoStorePath(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}
