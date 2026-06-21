package theauth

import (
	"encoding/json"
	"net/http"
	"time"
)

// decodeCredsBody reads the standard {email, password} JSON body with a 16 KiB cap.
// Returns ok=false after writing a 400 response if parsing fails.
func decodeCredsBody(w http.ResponseWriter, r *http.Request) (email, password string, ok bool) {
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

func (a *TheAuth) handlePasswordSignup(w http.ResponseWriter, r *http.Request) {
	email, password, ok := decodeCredsBody(w, r)
	if !ok {
		return
	}
	_, sessToken, err := a.signupWithPassword(r.Context(), email, password)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	a.setSessionCookie(w, sessToken)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (a *TheAuth) handlePasswordSignin(w http.ResponseWriter, r *http.Request) {
	email, password, ok := decodeCredsBody(w, r)
	if !ok {
		return
	}
	ip := extractClientIP(r)
	ua := r.UserAgent()
	sessToken, _, step, err := a.signinWithPassword(r.Context(), email, password, ua, ip)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	a.setSessionCookie(w, sessToken)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if step == SigninStepTOTPRequired {
		// v0.5 step-up: tell the client the cookie is pending and the
		// next call must be /auth/totp/verify (or /auth/totp/recovery).
		_, _ = w.Write([]byte(`{"step":"totp_required"}`))
		return
	}
	_, _ = w.Write([]byte(`{"ok":true,"step":"full"}`))
}

func (a *TheAuth) handlePasswordForgot(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if err := a.requestPasswordReset(r.Context(), body.Email); err != nil {
		errToHTTP(w, err)
		return
	}
	// Always 200 — silent on unknown email is enforced in the service layer.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"sent":true}`))
}

func (a *TheAuth) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
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
	if err := a.resetPassword(r.Context(), body.Token, body.NewPassword); err != nil {
		errToHTTP(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// setSessionCookie writes the standard session cookie for password endpoints.
// Mirrors the magic-link-verify cookie semantics so /auth/me works the same
// way regardless of which signin path was used.
func (a *TheAuth) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(a.sessionTTL),
	})
}
