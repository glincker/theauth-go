// Package handlers exposes the /auth/totp/* HTTP endpoints for TOTP
// 2FA enrollment, verification, recovery, and removal.
//
// Extracted from root handlers_totp.go in PR E of the 2026-06
// architecture reorg. The root *theauth.TheAuth constructs a Handler
// here and Mount is invoked from a thin mountTOTPHandlers forwarder
// so the public surface and route shapes are unchanged.
package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/internal/httpx"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/totp"
	"github.com/go-chi/chi/v5"
)

// CookieConfig captures the session cookie shape (name, secure, TTL)
// needed to refresh the session cookie after a successful verify or
// recovery flow.
type CookieConfig struct {
	Name       string
	SecureFlag bool
	TTL        time.Duration
}

// Handler owns the five TOTP HTTP endpoints. The userFromCtx
// indirection lets us pull the authenticated user without importing
// the root package.
type Handler struct {
	svc         *totp.Service
	cookie      CookieConfig
	userFromCtx func(r *http.Request) (*models.User, bool)
}

// New constructs a Handler. userFromCtx is invoked on requests that
// run through RequireAuth (enroll/begin, enroll/finish, delete) to
// pull the user out of the chi-attached request context.
func New(svc *totp.Service, cookie CookieConfig, userFromCtx func(r *http.Request) (*models.User, bool)) *Handler {
	return &Handler{svc: svc, cookie: cookie, userFromCtx: userFromCtx}
}

// Mount registers /totp/* under r. The caller supplies the ipLimit
// rate-limit middleware, the requireAuth middleware (for begin/finish/
// delete), and the requirePendingOrFull middleware (for verify/
// recovery) so all auth + rate-limit state stays owned by root.
func (h *Handler) Mount(r chi.Router, ipLimit, requireAuth, requirePendingOrFull func(http.Handler) http.Handler) {
	r.Route("/totp", func(r chi.Router) {
		r.With(ipLimit, requireAuth).Post("/enroll/begin", h.handleEnrollBegin)
		r.With(ipLimit, requireAuth).Post("/enroll/finish", h.handleEnrollFinish)
		r.With(ipLimit, requirePendingOrFull).Post("/verify", h.handleVerify)
		r.With(ipLimit, requirePendingOrFull).Post("/recovery", h.handleRecovery)
		r.With(requireAuth).Delete("/", h.handleDelete)
	})
}

func (h *Handler) handleEnrollBegin(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	res, err := h.svc.BeginEnrollment(r.Context(), user.ID, user.Email)
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (h *Handler) handleEnrollFinish(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var body struct {
		EnrollmentID string `json:"enrollmentId"`
		Code         string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.EnrollmentID == "" || body.Code == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	rc, err := h.svc.FinishEnrollment(r.Context(), user.ID, body.EnrollmentID, body.Code)
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}{RecoveryCodes: rc})
}

func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cookie.Name)
	if err != nil || cookie.Value == "" {
		http.Error(w, "missing session", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Code == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	tok, _, err := h.svc.Verify(r.Context(), cookie.Value, body.Code)
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	h.setSessionCookie(w, tok)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"step":"full"}`))
}

func (h *Handler) handleRecovery(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cookie.Name)
	if err != nil || cookie.Value == "" {
		http.Error(w, "missing session", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Code == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	tok, _, err := h.svc.ConsumeRecoveryCode(r.Context(), cookie.Value, body.Code)
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	h.setSessionCookie(w, tok)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"step":"full"}`))
}

func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	if err := h.svc.Delete(r.Context(), user.ID); err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setSessionCookie writes the same session cookie shape root uses so
// /auth/me works identically regardless of which signin path was used.
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
