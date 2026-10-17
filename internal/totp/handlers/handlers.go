// Package handlers exposes the /auth/totp/* endpoints for TOTP enrollment, verification, recovery and
// removal.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/totp"
	"github.com/go-chi/chi/v5"
)

// Service is the TOTP surface this package's HTTP handlers need. The
// root *theauth.TheAuth constructs an adapter satisfying this interface
// (rather than passing *totp.Service directly) so FinishEnrollment
// dispatches through the root forwarder that fires
// LifecycleHooks.OnMFAEnabled. Passing the raw internal Service here
// would silently skip that hook.
type Service interface {
	BeginEnrollment(ctx context.Context, userID models.ULID, accountName string) (totp.EnrollResult, error)
	FinishEnrollment(ctx context.Context, userID models.ULID, enrollmentID, code string) ([]string, error)
	Verify(ctx context.Context, pendingSessionToken, code string) (string, models.Session, error)
	ConsumeRecoveryCode(ctx context.Context, pendingSessionToken, code string) (string, models.Session, error)
	Delete(ctx context.Context, userID models.ULID) error
	Status(ctx context.Context, userID models.ULID) (totp.Status, error)
	RegenerateRecoveryCodes(ctx context.Context, userID models.ULID) ([]string, error)
}

// DeviceRemember is the optional Service capability behind "remember this
// device". It stores a trusted-device record and returns the cookie value
// and its expiry.
type DeviceRemember interface {
	RememberDevice(ctx context.Context, userID models.ULID, userAgent, ip string) (cookieValue string, expires time.Time, err error)
}

// CookieConfig captures the session cookie shape (name, secure, TTL)
// needed to refresh the session cookie after a successful verify or
// recovery flow.
type CookieConfig struct {
	Name       string
	SecureFlag bool
	TTL        time.Duration
	// DeviceCookieName, when set together with a Service that implements
	// DeviceRemember, enables the rememberDevice body flag on verify and
	// recovery.
	DeviceCookieName string
}

// Handler owns the five TOTP HTTP endpoints. The userFromCtx
// indirection lets us pull the authenticated user without importing
// the root package.
type Handler struct {
	svc         Service
	cookie      CookieConfig
	userFromCtx func(r *http.Request) (*models.User, bool)
}

// New constructs a Handler. userFromCtx is invoked on requests that
// run through RequireAuth (enroll/begin, enroll/finish, delete) to
// pull the user out of the chi-attached request context.
func New(svc Service, cookie CookieConfig, userFromCtx func(r *http.Request) (*models.User, bool)) *Handler {
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
		r.With(requireAuth).Get("/", h.handleStatus)
		r.With(ipLimit, requireAuth).Post("/recovery-codes", h.handleRegenerate)
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
		httpx.Error(w, http.StatusBadRequest, "invalid body")
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
		httpx.Error(w, http.StatusUnauthorized, "missing session")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var body struct {
		Code           string `json:"code"`
		RememberDevice bool   `json:"rememberDevice"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Code == "" {
		httpx.Error(w, http.StatusBadRequest, "invalid body")
		return
	}
	tok, sess, err := h.svc.Verify(r.Context(), cookie.Value, body.Code)
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	h.setSessionCookie(w, tok)
	h.rememberDevice(w, r, body.RememberDevice, sess.UserID)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"step":"full"}`))
}

func (h *Handler) handleRecovery(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cookie.Name)
	if err != nil || cookie.Value == "" {
		httpx.Error(w, http.StatusUnauthorized, "missing session")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var body struct {
		Code           string `json:"code"`
		RememberDevice bool   `json:"rememberDevice"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Code == "" {
		httpx.Error(w, http.StatusBadRequest, "invalid body")
		return
	}
	tok, sess, err := h.svc.ConsumeRecoveryCode(r.Context(), cookie.Value, body.Code)
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	h.setSessionCookie(w, tok)
	h.rememberDevice(w, r, body.RememberDevice, sess.UserID)
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

// rememberDevice sets the trusted-device cookie after a successful second
// factor when the client asked for it and the feature is enabled. A failure
// is logged and ignored: the user is signed in either way.
func (h *Handler) rememberDevice(w http.ResponseWriter, r *http.Request, want bool, userID models.ULID) {
	if !want || h.cookie.DeviceCookieName == "" {
		return
	}
	dr, ok := h.svc.(DeviceRemember)
	if !ok {
		return
	}
	val, exp, err := dr.RememberDevice(r.Context(), userID, r.UserAgent(), httpx.ClientIP(r))
	if err != nil {
		slog.Warn("theauth: remember device failed", "user_id", userID.String(), "err", err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{ // NOSONAR go:S2092 Secure follows the configured session cookie policy
		Name:     h.cookie.DeviceCookieName,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		// SecureFlag is the same setting the session cookie uses. It is true
		// whenever BaseURL is https, and false only for plain http development.
		Secure:   h.cookie.SecureFlag,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
	})
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	st, err := h.svc.Status(r.Context(), user.ID)
	if err != nil {
		httpx.ErrToHTTP(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *Handler) handleRegenerate(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	codes, err := h.svc.RegenerateRecoveryCodes(r.Context(), user.ID)
	switch {
	case errors.Is(err, totp.ErrNotEnrolled):
		http.Error(w, "totp not enrolled", http.StatusConflict)
		return
	case errors.Is(err, totp.ErrRecoveryUnsupported):
		http.Error(w, "recovery code management not supported by storage", http.StatusNotImplemented)
		return
	case err != nil:
		httpx.ErrToHTTP(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}{RecoveryCodes: codes})
}
