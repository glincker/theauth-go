// Package handlers exposes the /auth/providers/{name}/start and /callback endpoints for user-facing OAuth
// login (Google, GitHub, Discord, Microsoft). The OAuth service is reached through a small Service interface.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/v2/internal/httpsec"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/oauth"
	"github.com/go-chi/chi/v5"
)

// oauthStateCookieName is the short-lived browser-binding cookie set at
// /start; its value is a secret distinct from the state parameter and is
// verified server-side at /callback.
const oauthStateCookieName = "theauth_oauth_state"

// oauthStateCookieTTL caps the time between /start and provider
// redirect; matches the service-side oauthStateTTL.
const oauthStateCookieTTL = 10 * time.Minute

// Service is the minimum surface this handler needs from the OAuth
// service layer. Implemented by root *TheAuth (StartOAuth +
// CallbackOAuth wrappers) so this package does not import root.
type Service interface {
	HasProvider(name string) bool
	Start(ctx context.Context, r *http.Request, providerName, returnTo string) (oauth.StartResult, error)
	Callback(ctx context.Context, providerName, code, state, binding, userAgent, ip string) (oauth.CallbackResult, error)
}

// ProviderLookuper is optionally implemented by a Service whose providers
// can change at runtime; it lets the handler fail closed on a lookup error.
type ProviderLookuper interface {
	LookupProvider(ctx context.Context, name string) (bool, error)
}

// SessionCookieConfig is the session cookie shape used after a
// successful callback.
type SessionCookieConfig struct {
	Name       string
	SecureFlag bool
	TTL        time.Duration
	// Policy carries Domain, SameSite and Partitioned. Secure is SecureFlag OR Policy.Secure.
	Policy httpsec.CookiePolicy
}

// Handler owns the two OAuth user-login endpoints.
type Handler struct {
	svc               Service
	sessionCookie     SessionCookieConfig
	postLoginRedirect string
	clientIP          func(*http.Request) string
}

// New constructs a Handler. postLoginRedirect is the URL the browser
// is sent to after a successful callback.
func New(svc Service, sessionCookie SessionCookieConfig, postLoginRedirect string) *Handler {
	return &Handler{svc: svc, sessionCookie: sessionCookie, postLoginRedirect: postLoginRedirect}
}

// SetClientIP installs the function that derives the client address for throttling, audit and
// session records. The default is the connection address; the root installs a resolver that
// honors Config.TrustedProxies. A nil fn is ignored.
func (h *Handler) SetClientIP(fn func(*http.Request) string) {
	if fn != nil {
		h.clientIP = fn
	}
}

func (h *Handler) ipOf(r *http.Request) string {
	if h.clientIP != nil {
		return h.clientIP(r)
	}
	return httpx.ClientIP(r)
}

// Mount registers /providers/{name}/start and
// /providers/{name}/callback under r.
func (h *Handler) Mount(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	r.Route("/providers", func(r chi.Router) {
		r.With(ipLimit).Get("/{name}/start", h.handleStart)
		r.With(ipLimit).Get("/{name}/callback", h.handleCallback)
	})
}

func (h *Handler) providerOK(w http.ResponseWriter, r *http.Request, name string) bool {
	if lk, ok := h.svc.(ProviderLookuper); ok {
		found, err := lk.LookupProvider(r.Context(), name)
		if err != nil {
			http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
			return false
		}
		if !found {
			http.Error(w, "unknown provider", http.StatusNotFound)
			return false
		}
		return true
	}
	if !h.svc.HasProvider(name) {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return false
	}
	return true
}

func (h *Handler) handleStart(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if !h.providerOK(w, r, name) {
		return
	}
	res, err := h.svc.Start(r.Context(), r, name, r.URL.Query().Get("return_to"))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.setStateCookie(w, res.Binding)
	http.Redirect(w, r, res.AuthURL, http.StatusFound)
}

func (h *Handler) setStateCookie(w http.ResponseWriter, binding string) {
	h.stateCookiePolicy().
		Set(w, oauthStateCookieName, binding, "/", time.Now().Add(oauthStateCookieTTL))
}

// stateCookiePolicy is the session policy with Strict relaxed to Lax: the provider redirects back
// with a cross-site navigation that would not carry a Strict state cookie.
func (h *Handler) stateCookiePolicy() httpsec.CookiePolicy {
	return h.sessionCookie.Policy.WithSecure(h.sessionCookie.SecureFlag).ForCrossSiteReturn()
}

func (h *Handler) clearStateCookie(w http.ResponseWriter) {
	h.stateCookiePolicy().Clear(w, oauthStateCookieName, "/")
}

func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if !h.providerOK(w, r, name) {
		return
	}
	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		http.Error(w, "oauth provider error: "+errCode, http.StatusBadRequest)
		return
	}
	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}
	cookie, err := r.Cookie(oauthStateCookieName)
	if err != nil || cookie.Value == "" {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	h.clearStateCookie(w)

	res, err := h.svc.Callback(r.Context(), name, code, state, cookie.Value, r.UserAgent(), h.ipOf(r))
	if err != nil {
		var conflictRedirect *models.OAuthConflictRedirectError
		if errors.As(err, &conflictRedirect) {
			http.Redirect(w, r, conflictRedirect.URL, http.StatusFound)
			return
		}
		http.Error(w, "oauth callback failed", http.StatusBadRequest)
		return
	}
	h.setSessionCookie(w, res.SessionToken)
	dest := h.postLoginRedirect
	if res.ReturnTo != "" {
		dest = res.ReturnTo
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, token string) {
	h.sessionCookie.Policy.WithSecure(h.sessionCookie.SecureFlag).
		Set(w, h.sessionCookie.Name, token, "/", time.Now().Add(h.sessionCookie.TTL))
}
