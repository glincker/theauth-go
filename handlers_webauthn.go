package theauth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// webauthnChallengeCookieName is the short-lived cookie set at /begin and
// read at /finish that binds the ceremony's in-memory entry to the user
// agent (HttpOnly so JS cannot exfiltrate; SameSite=Lax matches the
// session cookie semantics).
const webauthnChallengeCookieName = "theauth_webauthn_chal"

// webauthnCookiePath scopes the challenge cookie to the WebAuthn route
// group so it isn't sent on unrelated requests.
const webauthnCookiePath = "/auth/webauthn"

// mountWebAuthn registers /auth/webauthn/* under r. Conditional on Config.WebAuthn
// being non-nil (the caller in Mount checks this).
func (a *TheAuth) mountWebAuthn(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	r.Route("/webauthn", func(r chi.Router) {
		r.With(ipLimit, a.RequireAuth()).Post("/register/begin", a.handleWebAuthnRegisterBegin)
		r.With(ipLimit, a.RequireAuth()).Post("/register/finish", a.handleWebAuthnRegisterFinish)
		r.With(ipLimit).Post("/login/begin", a.handleWebAuthnLoginBegin)
		r.With(ipLimit).Post("/login/finish", a.handleWebAuthnLoginFinish)
		r.With(a.RequireAuth()).Get("/credentials", a.handleWebAuthnCredentialsList)
		r.With(a.RequireAuth()).Delete("/credentials/{id}", a.handleWebAuthnCredentialsDelete)
	})
}

func (a *TheAuth) setWebAuthnChalCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     webauthnChallengeCookieName,
		Value:    token,
		Path:     webauthnCookiePath,
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(a.webauthnChalTTL),
	})
}

func (a *TheAuth) clearWebAuthnChalCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     webauthnChallengeCookieName,
		Value:    "",
		Path:     webauthnCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *TheAuth) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	creation, tok, err := a.BeginPasskeyRegistration(r.Context(), user.ID)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	a.setWebAuthnChalCookie(w, tok)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creation)
}

func (a *TheAuth) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	chal, err := r.Cookie(webauthnChallengeCookieName)
	if err != nil || chal.Value == "" {
		http.Error(w, "missing challenge cookie", http.StatusBadRequest)
		return
	}
	a.clearWebAuthnChalCookie(w)
	// The body may be a multipart form on some browsers, but v0.5 ships
	// JSON only; a 64 KiB cap prevents memory DoS.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	name := r.URL.Query().Get("name") // optional nickname
	cred, err := a.FinishPasskeyRegistration(r.Context(), user.ID, chal.Value, name, r.Body)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(cred)
}

func (a *TheAuth) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	assertion, tok, err := a.BeginPasskeyLogin(r.Context())
	if err != nil {
		errToHTTP(w, err)
		return
	}
	a.setWebAuthnChalCookie(w, tok)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(assertion)
}

func (a *TheAuth) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	chal, err := r.Cookie(webauthnChallengeCookieName)
	if err != nil || chal.Value == "" {
		http.Error(w, "missing challenge cookie", http.StatusBadRequest)
		return
	}
	a.clearWebAuthnChalCookie(w)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	sessTok, _, err := a.FinishPasskeyLogin(r.Context(), chal.Value, r.Body, r.UserAgent(), extractClientIP(r))
	if err != nil {
		errToHTTP(w, err)
		return
	}
	a.setSessionCookie(w, sessTok)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (a *TheAuth) handleWebAuthnCredentialsList(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	creds, err := a.storage.WebAuthnCredentialsByUserID(r.Context(), user.ID)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creds)
}

func (a *TheAuth) handleWebAuthnCredentialsDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	idStr := chi.URLParam(r, "id")
	id, err := parseULIDParam(idStr)
	if err != nil {
		http.Error(w, "invalid credential id", http.StatusBadRequest)
		return
	}
	if err := a.storage.DeleteWebAuthnCredential(r.Context(), id, user.ID); err != nil {
		errToHTTP(w, err)
		return
	}
	a.EmitAudit(r.Context(), "passkey.deleted", TargetRef{Type: "webauthn_credential", ID: id.String()}, nil)
	w.WriteHeader(http.StatusNoContent)
}
