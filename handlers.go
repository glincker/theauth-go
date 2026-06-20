package theauth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// Mount wires TheAuth's HTTP routes onto the supplied chi router under /auth.
// Routes:
//
//	POST   /auth/magic-link            request a magic link
//	GET    /auth/magic-link/verify     consume a magic link, set session cookie
//	GET    /auth/me                    return the authenticated user (RequireAuth)
//	DELETE /auth/sessions/current      revoke the current session (RequireAuth)
func (a *TheAuth) Mount(r chi.Router) {
	r.Route("/auth", func(r chi.Router) {
		r.Post("/magic-link", a.handleMagicLinkRequest)
		r.Get("/magic-link/verify", a.handleMagicLinkVerify)
		r.With(a.RequireAuth()).Delete("/sessions/current", a.handleSessionDelete)
		r.With(a.RequireAuth()).Get("/me", a.handleMe)
	})
}

func (a *TheAuth) handleMagicLinkRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14) // 16 KiB cap to prevent memory DoS
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	addr, err := mail.ParseAddress(body.Email)
	if err != nil {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(addr.Address))
	if err := a.requestMagicLink(r.Context(), email); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"sent":true}`))
}

func (a *TheAuth) handleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	sessToken, _, err := a.consumeMagicLink(r.Context(), token)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    sessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(a.sessionTTL),
	})
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (a *TheAuth) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(user)
}

func (a *TheAuth) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	sess, ok := SessionFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := a.storage.RevokeSession(r.Context(), sess.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	slog.Info("theauth: session revoked", "user_id", sess.UserID.String(), "session_id", sess.ID.String())
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func errToHTTP(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidToken),
		errors.Is(err, ErrMagicLinkExpired),
		errors.Is(err, ErrMagicLinkUsed),
		errors.Is(err, ErrSessionExpired):
		http.Error(w, err.Error(), http.StatusUnauthorized)
	case errors.Is(err, ErrUserNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
