package handlers

// handlers_oidc.go: OpenID Provider endpoints: userinfo and end_session.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/go-chi/chi/v5"
)

// SetSessionEnder installs the function that ends the request's browser
// session and clears its cookie. end_session calls it after the request
// validated. Nil leaves the session alone.
func (h *Handler) SetSessionEnder(fn func(w http.ResponseWriter, r *http.Request)) {
	h.sessionEnder = fn
}

func (h *Handler) mountOIDC(r chi.Router, authn func(http.Handler) http.Handler) {
	r.With(h.limited).Get("/oauth/userinfo", h.handleUserInfo)
	r.With(h.limited).Post("/oauth/userinfo", h.handleUserInfo)
	r.With(authn).Get("/oauth/end_session", h.handleEndSession)
	r.With(authn).Post("/oauth/end_session", h.handleEndSession)
}

// bearerToken extracts the access token and its auth scheme from the
// Authorization header, or from the access_token form field on POST.
func bearerToken(r *http.Request) (token, scheme string) {
	if v := r.Header.Get("Authorization"); v != "" {
		if i := strings.IndexByte(v, ' '); i > 0 {
			sc := strings.ToLower(v[:i])
			if sc == "bearer" || sc == "dpop" {
				return strings.TrimSpace(v[i+1:]), sc
			}
		}
		return "", ""
	}
	if r.Method == http.MethodPost {
		if t := r.PostFormValue("access_token"); t != "" {
			return t, "bearer"
		}
	}
	return "", ""
}

func (h *Handler) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	if !h.svc.OIDCEnabled() {
		http.NotFound(w, r)
		return
	}
	token, scheme := bearerToken(r)
	challenge := "Bearer"
	if scheme == "dpop" {
		challenge = "DPoP"
	}
	if token == "" {
		w.Header().Set("WWW-Authenticate", challenge+` realm="theauth"`)
		http.Error(w, "access token required", http.StatusUnauthorized)
		return
	}
	claims, err := h.svc.UserInfo(r.Context(), internalas.UserInfoRequest{
		AccessToken: token,
		DPoPProof:   r.Header.Get("DPoP"),
		HTTPMethod:  r.Method,
		HTTPURL:     h.svc.Cfg.Issuer + "/oauth/userinfo",
	})
	switch {
	case errors.Is(err, internalas.ErrUserInfoInsufficientScope):
		w.Header().Set("WWW-Authenticate", challenge+` realm="theauth", error="insufficient_scope", scope="openid"`)
		http.Error(w, "insufficient_scope", http.StatusForbidden)
		return
	case err != nil:
		w.Header().Set("WWW-Authenticate", challenge+` realm="theauth", error="invalid_token"`)
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(claims)
}

func (h *Handler) handleEndSession(w http.ResponseWriter, r *http.Request) {
	if !h.svc.OIDCEnabled() {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed form")
		return
	}
	req := internalas.EndSessionRequest{
		IDTokenHint:           r.Form.Get("id_token_hint"),
		ClientID:              r.Form.Get("client_id"),
		PostLogoutRedirectURI: r.Form.Get("post_logout_redirect_uri"),
		State:                 r.Form.Get("state"),
	}
	if user, ok := h.userFromCtx(r); ok && user != nil && h.authContext != nil {
		if ac, ok := h.authContext(r); ok && ac.SessionID != "" {
			req.SessionID = ac.SessionID
			uid := user.ID
			req.UserID = &uid
		}
	}
	res, err := h.svc.EndSession(r.Context(), req)
	if err != nil {
		if errors.Is(err, internalas.ErrEndSessionInvalid) {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, err.Error())
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if req.SessionID != "" && h.sessionEnder != nil {
		h.sessionEnder(w, r)
	}
	w.Header().Set("Cache-Control", "no-store")
	if res.RedirectURL != "" {
		http.Redirect(w, r, res.RedirectURL, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("<!doctype html><title>Signed out</title><p>You have been signed out.</p>"))
}
