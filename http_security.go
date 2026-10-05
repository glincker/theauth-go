package theauth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
)

const secureCookieAttr = "Secure"

// Handler returns a stdlib http.Handler serving every route Mount would
// register, for consumers on net/http's ServeMux without chi. Routes keep
// their canonical paths (/auth/..., /oauth/...); to serve under a prefix,
// wrap with http.StripPrefix.
func (a *TheAuth) Handler() http.Handler {
	r := chi.NewRouter()
	a.Mount(r)
	return r
}

// securityMiddleware applies per-request Secure cookie derivation and the
// Origin check ahead of every route Mount registers.
func (a *TheAuth) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.csrfDisabled && !a.originAllowed(r) {
			writeJSONError(w, http.StatusForbidden, "csrf_origin_rejected", "request origin is not trusted")
			return
		}
		if a.requestIsSecure(r) {
			w = &secureCookieWriter{ResponseWriter: w}
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
	if len(a.trustedProxies) > 0 && remoteIsTrusted(remoteAddrHost(r), a.trustedProxies) {
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

// secureCookieWriter adds the Secure attribute to every Set-Cookie header
// at write time, so handlers in internal packages need no per-request flag.
type secureCookieWriter struct {
	http.ResponseWriter
	done bool
}

func (w *secureCookieWriter) upgrade() {
	if w.done {
		return
	}
	w.done = true
	h := w.Header()
	cookies := h.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, c := range cookies {
		if !hasSecureAttr(c) {
			c += "; " + secureCookieAttr
		}
		h.Add("Set-Cookie", c)
	}
}

func hasSecureAttr(cookie string) bool {
	for _, part := range strings.Split(cookie, ";")[1:] {
		if strings.EqualFold(strings.TrimSpace(part), secureCookieAttr) {
			return true
		}
	}
	return false
}

func (w *secureCookieWriter) WriteHeader(code int) {
	w.upgrade()
	w.ResponseWriter.WriteHeader(code)
}

func (w *secureCookieWriter) Write(b []byte) (int, error) {
	w.upgrade()
	return w.ResponseWriter.Write(b)
}

func (w *secureCookieWriter) Flush() {
	w.upgrade()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach Hijack and deadlines.
func (w *secureCookieWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// originAllowed implements the CSRF defence for cookie-authenticated
// state-changing requests. Safe methods and bearer-token requests are
// exempt. A request that carries cookies must present an Origin (or
// Referer) in the trusted set; with neither header, Sec-Fetch-Site decides
// when the browser sent it. SameSite=Lax alone does not stop sibling
// subdomains, which are same-site.
func (a *TheAuth) originAllowed(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Authorization")), "bearer ") {
		return true
	}
	if r.Header.Get("Cookie") == "" {
		return true
	}
	if o := r.Header.Get("Origin"); o != "" {
		return a.originTrusted(o)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return a.originTrusted(ref)
	}
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "cross-site", "same-site":
		return false
	}
	return true
}

func (a *TheAuth) originTrusted(raw string) bool {
	o, ok := originOf(raw)
	if !ok {
		return false
	}
	if b, ok := originOf(a.baseURL); ok && b == o {
		return true
	}
	for _, t := range a.trustedOrigins {
		if t == o {
			return true
		}
	}
	return false
}

// originOf reduces a URL to a lowercase scheme://host[:port] string.
func originOf(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), true
}

// normalizeOrigins canonicalizes Config.TrustedOrigins entries.
func normalizeOrigins(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		o, ok := originOf(raw)
		if !ok {
			return nil, &originError{raw}
		}
		out = append(out, o)
	}
	return out, nil
}

type originError struct{ raw string }

func (e *originError) Error() string {
	return "theauth: Config.TrustedOrigins entry " + e.raw + " is not an absolute origin URL"
}
