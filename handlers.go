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
//	POST   /auth/magic-link                       request a magic link
//	GET    /auth/magic-link/verify                consume a magic link, set session cookie
//	POST   /auth/email-password/signup            create user with email + password (rate-limited)
//	POST   /auth/email-password/signin            sign in with email + password (rate-limited)
//	POST   /auth/email-password/forgot            request a password reset link (rate-limited)
//	POST   /auth/email-password/reset             consume a reset token + set new password (rate-limited)
//	GET    /auth/me                               return the authenticated user (RequireAuth)
//	DELETE /auth/sessions/current                 revoke the current session (RequireAuth)
//
// Default rate limits: 5/min per source IP on every credential endpoint, plus
// 3/min per email on signin + forgot (most attack-surface). All limits are
// in-memory + per-process; replace at the LB layer for multi-instance deploys.
func (a *TheAuth) Mount(r chi.Router) {
	// Build limiter middlewares once so the same buckets persist across all
	// routes mounted at this point. Re-mounting builds a fresh set.
	ipLimit := a.RateLimitByIP(5)
	emailLimit := a.RateLimitByEmail(3)

	r.Route("/auth", func(r chi.Router) {
		r.Post("/magic-link", a.handleMagicLinkRequest)
		r.Get("/magic-link/verify", a.handleMagicLinkVerify)

		r.Route("/email-password", func(r chi.Router) {
			r.With(ipLimit).Post("/signup", a.handlePasswordSignup)
			r.With(ipLimit, emailLimit).Post("/signin", a.handlePasswordSignin)
			r.With(ipLimit, emailLimit).Post("/forgot", a.handlePasswordForgot)
			r.With(ipLimit).Post("/reset", a.handlePasswordReset)
		})

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
	// Prefer the new TheAuthError code mapping when available — gives callers
	// a stable Code field in the response body for programmatic handling.
	var te *TheAuthError
	if errors.As(err, &te) {
		switch te.Code {
		case CodeWeakPassword:
			writeJSONError(w, http.StatusBadRequest, te.Code, te.Message)
		case CodeEmailTaken:
			writeJSONError(w, http.StatusConflict, te.Code, te.Message)
		case CodeInvalidCredentials:
			writeJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		case CodeRateLimited:
			writeJSONError(w, http.StatusTooManyRequests, te.Code, te.Message)
		case CodePasswordResetExpired, CodePasswordResetInvalid:
			writeJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		default:
			writeJSONError(w, http.StatusInternalServerError, te.Code, "internal error")
		}
		return
	}
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

// writeJSONError emits the v0.2+ error response shape: {"code":"...","message":"..."}.
// Old (v0.1) error responses still use plain-text http.Error for backward compat.
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message})
}
