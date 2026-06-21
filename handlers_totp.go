package theauth

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// mountTOTP registers /auth/totp/* under r. Conditional on Config.TOTP being
// non-nil (the caller in Mount checks this).
func (a *TheAuth) mountTOTP(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	r.Route("/totp", func(r chi.Router) {
		r.With(ipLimit, a.RequireAuth()).Post("/enroll/begin", a.handleTOTPEnrollBegin)
		r.With(ipLimit, a.RequireAuth()).Post("/enroll/finish", a.handleTOTPEnrollFinish)
		r.With(ipLimit, a.RequirePendingOrFull()).Post("/verify", a.handleTOTPVerify)
		r.With(ipLimit, a.RequirePendingOrFull()).Post("/recovery", a.handleTOTPRecovery)
		r.With(a.RequireAuth()).Delete("/", a.handleTOTPDelete)
	})
}

func (a *TheAuth) handleTOTPEnrollBegin(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	res, err := a.BeginTOTPEnrollment(r.Context(), user.ID, user.Email)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (a *TheAuth) handleTOTPEnrollFinish(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var body struct {
		EnrollmentID string `json:"enrollmentId"`
		Code         string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.EnrollmentID == "" || body.Code == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	rc, err := a.FinishTOTPEnrollment(r.Context(), user.ID, body.EnrollmentID, body.Code)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}{RecoveryCodes: rc})
}

func (a *TheAuth) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(a.cookieName)
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
	tok, _, err := a.VerifyTOTP(r.Context(), cookie.Value, body.Code)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	// Re-emit the cookie with the same token so the browser keeps a fresh
	// Expires stamp post-promotion.
	a.setSessionCookie(w, tok)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"step":"full"}`))
}

func (a *TheAuth) handleTOTPRecovery(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(a.cookieName)
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
	tok, _, err := a.ConsumeRecoveryCode(r.Context(), cookie.Value, body.Code)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	a.setSessionCookie(w, tok)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"step":"full"}`))
}

func (a *TheAuth) handleTOTPDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	if err := a.storage.DeleteTOTPSecret(r.Context(), user.ID); err != nil {
		errToHTTP(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
