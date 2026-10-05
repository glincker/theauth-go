// Package httpsec holds the Secure cookie rewriting and the Origin allowlist check.
package httpsec

import (
	"net/http"
	"net/url"
	"strings"
)

// SecureCookieAttr is the cookie attribute CookieWriter appends.
const SecureCookieAttr = "Secure"

// CookieWriter adds the Secure attribute to every Set-Cookie header
// at write time, so handlers in internal packages need no per-request flag.
type CookieWriter struct {
	http.ResponseWriter
	done bool
}

// NewCookieWriter wraps w so every Set-Cookie carries Secure.
func NewCookieWriter(w http.ResponseWriter) *CookieWriter { return &CookieWriter{ResponseWriter: w} }

func (w *CookieWriter) upgrade() {
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
			c += "; " + SecureCookieAttr
		}
		h.Add("Set-Cookie", c)
	}
}

func hasSecureAttr(cookie string) bool {
	for _, part := range strings.Split(cookie, ";")[1:] {
		if strings.EqualFold(strings.TrimSpace(part), SecureCookieAttr) {
			return true
		}
	}
	return false
}

func (w *CookieWriter) WriteHeader(code int) {
	w.upgrade()
	w.ResponseWriter.WriteHeader(code)
}

func (w *CookieWriter) Write(b []byte) (int, error) {
	w.upgrade()
	return w.ResponseWriter.Write(b)
}

func (w *CookieWriter) Flush() {
	w.upgrade()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach Hijack and deadlines.
func (w *CookieWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// OriginAllowed implements the CSRF defence for cookie-authenticated
// state-changing requests. Safe methods and bearer-token requests are
// exempt. A request that carries cookies must present an Origin (or
// Referer) in the trusted set; with neither header, Sec-Fetch-Site decides
// when the browser sent it. SameSite=Lax alone does not stop sibling
// subdomains, which are same-site.
func OriginAllowed(r *http.Request, baseURL string, trusted []string) bool {
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
		return originTrusted(baseURL, trusted, o)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return originTrusted(baseURL, trusted, ref)
	}
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "cross-site", "same-site":
		return false
	}
	return true
}

func originTrusted(baseURL string, trusted []string, raw string) bool {
	o, ok := originOf(raw)
	if !ok {
		return false
	}
	if b, ok := originOf(baseURL); ok && b == o {
		return true
	}
	for _, t := range trusted {
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

// NormalizeOrigins canonicalizes Config.TrustedOrigins entries.
func NormalizeOrigins(in []string) ([]string, error) {
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
