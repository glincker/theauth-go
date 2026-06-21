// Package handlers exposes the /auth/email-password/* HTTP endpoints
// for password signup, signin, forgot, and reset.
//
// Extracted from root handlers_password.go in PR E of the 2026-06
// architecture reorg. The root *theauth.TheAuth constructs a Handler
// here and forwards Mount to it from the package-level Mount function
// so the public surface and route shapes are unchanged.
package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/internal/httpx"
	"github.com/glincker/theauth-go/internal/password"
	"github.com/go-chi/chi/v5"
)

// CookieConfig captures the session cookie attributes the password
// flow needs to mint a Set-Cookie. Owned by the root TheAuth and
// passed by value at construction so this package does not import the
// root.
type CookieConfig struct {
	Name       string
	SecureFlag bool
	TTL        time.Duration
}

// Handler owns the four password HTTP endpoints. It depends on the
// extracted password Service for business logic and on a CookieConfig
// for the session cookie shape.
type Handler struct {
	svc    *password.Service
	cookie CookieConfig
}

// New constructs a Handler. Both arguments are required; pass a real
// password.Service constructed by the root and a populated CookieConfig
// matching the operator session settings.
func New(svc *password.Service, cookie CookieConfig) *Handler {
	return &Handler{svc: svc, cookie: cookie}
}

// Mount registers the /email-password/* subroutes onto r. The caller
// supplies ipLimit + emailLimit middlewares so the bucket state stays
// owned by the root middleware layer (PR E does not extract the
// middleware).
func (h *Handler) Mount(r chi.Router, ipLimit, emailLimit func(http.Handler) http.Handler) {
	r.With(ipLimit).Post("/signup", h.handleSignup)
	r.With(ipLimit, emailLimit).Post("/signin", h.handleSignin)
	r.With(ipLimit, emailLimit).Post("/forgot", h.handleForgot)
	r.With(ipLimit).Post("/reset", h.handleReset)
}

// decodeCredsBody reads the standard {email, password} JSON body with
// a 16 KiB cap. Returns ok=false after writing a 400 response if
// parsing fails.
func decodeCredsBody(w http.ResponseWriter, r *http.Request) (email, pw string, ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return "", "", false
	}
	if body.Email == "" || body.Password == "" {
		http.Error(w, "email and password are required", http.StatusBadRequest)
		return "", "", false
	}
	return body.Email, body.Password, true
}

func (h *Handler) handleSignup(w http.ResponseWriter, r *http.Request) {
	email, pw, ok := decodeCredsBody(w, r)
	if !ok {
		return
	}
	_, sessToken, err := h.svc.Signup(r.Context(), email, pw)
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	h.setSessionCookie(w, sessToken)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) handleSignin(w http.ResponseWriter, r *http.Request) {
	email, pw, ok := decodeCredsBody(w, r)
	if !ok {
		return
	}
	ip := httpx.ClientIP(r)
	ua := r.UserAgent()
	sessToken, _, step, err := h.svc.Signin(r.Context(), email, pw, ua, ip)
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	h.setSessionCookie(w, sessToken)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if step == password.SigninStepTOTPRequired {
		_, _ = w.Write([]byte(`{"step":"totp_required"}`))
		return
	}
	_, _ = w.Write([]byte(`{"ok":true,"step":"full"}`))
}

func (h *Handler) handleForgot(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if err := h.svc.RequestReset(r.Context(), body.Email); err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"sent":true}`))
}

func (h *Handler) handleReset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var body struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.Token == "" || body.NewPassword == "" {
		http.Error(w, "token and newPassword are required", http.StatusBadRequest)
		return
	}
	if err := h.svc.Reset(r.Context(), body.Token, body.NewPassword); err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// setSessionCookie writes the session cookie for password endpoints.
// Mirrors the magic-link-verify cookie semantics so /auth/me works the
// same regardless of which signin path was used.
func (h *Handler) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.cookie.Name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookie.SecureFlag,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(h.cookie.TTL),
	})
}
