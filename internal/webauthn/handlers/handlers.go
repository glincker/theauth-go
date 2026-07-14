// Package handlers exposes the /auth/webauthn/* HTTP endpoints for
// passkey registration, authentication, and credential management.
//
// Extracted from root handlers_webauthn.go in PR E of the 2026-06
// architecture reorg. The root *theauth.TheAuth constructs a Handler
// here and Mount is invoked from a thin mountWebAuthn forwarder so
// the public surface and route shapes are unchanged.
package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/internal/httpx"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
)

// Service is the WebAuthn surface this package's HTTP handlers need. The
// root *theauth.TheAuth constructs an adapter satisfying this interface
// (rather than passing *webauthn.Service directly) so FinishRegistration
// dispatches through the root forwarder that fires
// LifecycleHooks.OnSignup on a user's first credential. Passing the raw
// internal Service here would silently skip that hook.
type Service interface {
	BeginRegistration(ctx context.Context, userID models.ULID) (*protocol.CredentialCreation, string, error)
	FinishRegistration(ctx context.Context, userID models.ULID, challengeToken, name string, body io.Reader) (models.WebAuthnCredential, error)
	BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error)
	FinishLogin(ctx context.Context, challengeToken string, body io.Reader, ua, ip string) (string, models.Session, error)
	ListCredentials(ctx context.Context, userID models.ULID) ([]models.WebAuthnCredential, error)
	DeleteCredential(ctx context.Context, id, userID models.ULID) error
}

// webauthnChallengeCookieName is the short-lived cookie set at /begin
// and read at /finish that binds the in-memory ceremony entry to the
// user agent. HttpOnly + SameSite=Lax mirrors the session cookie.
const webauthnChallengeCookieName = "theauth_webauthn_chal"

// webauthnCookiePath scopes the challenge cookie to the WebAuthn
// route group so it is not sent on unrelated requests.
const webauthnCookiePath = "/auth/webauthn"

// SessionCookieConfig captures the session cookie shape needed after
// a successful FinishLogin.
type SessionCookieConfig struct {
	Name       string
	SecureFlag bool
	TTL        time.Duration
}

// ChallengeCookieConfig captures the challenge cookie shape (just
// SecureFlag + TTL; Name + Path are constants above).
type ChallengeCookieConfig struct {
	SecureFlag bool
	TTL        time.Duration
}

// Handler owns the six WebAuthn HTTP endpoints.
type Handler struct {
	svc           Service
	sessionCookie SessionCookieConfig
	challengeCfg  ChallengeCookieConfig
	userFromCtx   func(r *http.Request) (*models.User, bool)
}

// New constructs a Handler. The userFromCtx indirection lets the
// register and credential endpoints pull the authenticated user out
// of the request context without importing the root.
func New(
	svc Service,
	sessionCookie SessionCookieConfig,
	challengeCfg ChallengeCookieConfig,
	userFromCtx func(r *http.Request) (*models.User, bool),
) *Handler {
	return &Handler{
		svc:           svc,
		sessionCookie: sessionCookie,
		challengeCfg:  challengeCfg,
		userFromCtx:   userFromCtx,
	}
}

// Mount registers /webauthn/* under r. The caller supplies the
// ipLimit rate-limit middleware and the requireAuth middleware so the
// auth + rate-limit state stays owned by root.
func (h *Handler) Mount(r chi.Router, ipLimit, requireAuth func(http.Handler) http.Handler) {
	r.Route("/webauthn", func(r chi.Router) {
		r.With(ipLimit, requireAuth).Post("/register/begin", h.handleRegisterBegin)
		r.With(ipLimit, requireAuth).Post("/register/finish", h.handleRegisterFinish)
		r.With(ipLimit).Post("/login/begin", h.handleLoginBegin)
		r.With(ipLimit).Post("/login/finish", h.handleLoginFinish)
		r.With(requireAuth).Get("/credentials", h.handleCredentialsList)
		r.With(requireAuth).Delete("/credentials/{id}", h.handleCredentialsDelete)
	})
}

func (h *Handler) setChallengeCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     webauthnChallengeCookieName,
		Value:    token,
		Path:     webauthnCookiePath,
		HttpOnly: true,
		Secure:   h.challengeCfg.SecureFlag,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(h.challengeCfg.TTL),
	})
}

func (h *Handler) clearChallengeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     webauthnChallengeCookieName,
		Value:    "",
		Path:     webauthnCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.challengeCfg.SecureFlag,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.sessionCookie.Name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.sessionCookie.SecureFlag,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(h.sessionCookie.TTL),
	})
}

func (h *Handler) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	creation, tok, err := h.svc.BeginRegistration(r.Context(), user.ID)
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	h.setChallengeCookie(w, tok)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creation)
}

func (h *Handler) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	chal, err := r.Cookie(webauthnChallengeCookieName)
	if err != nil || chal.Value == "" {
		http.Error(w, "missing challenge cookie", http.StatusBadRequest)
		return
	}
	h.clearChallengeCookie(w)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	name := r.URL.Query().Get("name")
	cred, err := h.svc.FinishRegistration(r.Context(), user.ID, chal.Value, name, r.Body)
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(cred)
}

func (h *Handler) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	assertion, tok, err := h.svc.BeginLogin(r.Context())
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	h.setChallengeCookie(w, tok)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(assertion)
}

func (h *Handler) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	chal, err := r.Cookie(webauthnChallengeCookieName)
	if err != nil || chal.Value == "" {
		http.Error(w, "missing challenge cookie", http.StatusBadRequest)
		return
	}
	h.clearChallengeCookie(w)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	sessTok, _, err := h.svc.FinishLogin(r.Context(), chal.Value, r.Body, r.UserAgent(), httpx.ClientIP(r))
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	h.setSessionCookie(w, sessTok)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) handleCredentialsList(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	creds, err := h.svc.ListCredentials(r.Context(), user.ID)
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creds)
}

func (h *Handler) handleCredentialsDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	idStr := chi.URLParam(r, "id")
	id, err := httpx.ParseULIDParam(idStr)
	if err != nil {
		http.Error(w, "invalid credential id", http.StatusBadRequest)
		return
	}
	if err := h.svc.DeleteCredential(r.Context(), id, user.ID); err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
