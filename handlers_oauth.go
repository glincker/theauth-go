package theauth

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// oauthStateCookieName is the short-lived cookie set at /start carrying the
// CSRF state token. The /callback handler compares it to the state query
// param before doing anything else; mismatch -> 400.
const oauthStateCookieName = "theauth_oauth_state"

// oauthStateCookieTTL caps how long the user has between /start and the
// provider's redirect back to /callback. Matches oauthStateTTL on the
// service side.
const oauthStateCookieTTL = 10 * time.Minute

func (a *TheAuth) mountOAuth(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	r.Route("/providers", func(r chi.Router) {
		r.With(ipLimit).Get("/{name}/start", a.handleOAuthStart)
		r.With(ipLimit).Get("/{name}/callback", a.handleOAuthCallback)
	})
}

func (a *TheAuth) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if _, ok := a.providers[name]; !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}
	authURL, state, err := a.startOAuth(r.Context(), name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(oauthStateCookieTTL),
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *TheAuth) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if _, ok := a.providers[name]; !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		// Provider rejected the user (denied consent, invalid client, etc).
		// Surface a generic 400; production callers can layer a friendlier
		// page on top by handling this status.
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
	if err != nil || cookie.Value == "" || cookie.Value != state {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	// Clear the state cookie regardless of outcome below.
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})

	sessToken, _, err := a.callbackOAuth(r.Context(), name, code, state, r.UserAgent(), extractClientIP(r))
	if err != nil {
		http.Error(w, "oauth callback failed", http.StatusBadRequest)
		return
	}
	a.setSessionCookie(w, sessToken)
	http.Redirect(w, r, a.postLoginRedirect, http.StatusFound)
}
