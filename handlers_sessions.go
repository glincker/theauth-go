package theauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/internal/httpx"
	"github.com/go-chi/chi/v5"
)

const sessionBodyLimit = 1 << 16

func (a *TheAuth) mountSessionManagement(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	auth := a.RequireAuth()
	if a.sx.mgmt != nil {
		r.With(auth).Get("/sessions", a.handleSessionList)
		r.With(auth).Delete("/sessions/{id}", a.handleSessionRevokeByID)
		r.With(auth).Post("/sessions/revoke-others", a.handleSessionRevokeOthers)
		r.With(auth, ipLimit).Post("/step-up", a.handleStepUp)
		if a.webauthnCfg != nil {
			r.With(auth, ipLimit).Post("/step-up/passkey/begin", a.handleStepUpPasskeyBegin)
		}
	}
	r.With(auth, ipLimit).Post("/password/change", a.handlePasswordChange)
	if a.sx.linksCfg != nil {
		r.With(ipLimit).Post("/session-link/consume", a.handleSessionLinkConsume)
	}
}

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

func (a *TheAuth) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeSessionBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, sessionBodyLimit)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "invalid request body")
		return false
	}
	return true
}

func (a *TheAuth) handleSessionList(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	list, err := a.ListSessions(r.Context(), sess.UserID, sess.ID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

func (a *TheAuth) handleSessionRevokeByID(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	id, err := httpx.ParseULIDParam(chi.URLParam(r, "id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	if err := a.RevokeOwnedSession(r.Context(), sess.UserID, id); err != nil {
		if errors.Is(err, ErrStorageNotFound) {
			writeJSONError(w, http.StatusNotFound, "not_found", "session not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if id == sess.ID {
		a.clearSessionCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *TheAuth) handleSessionRevokeOthers(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	n, err := a.RevokeOtherSessions(r.Context(), sess.UserID, sess.ID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

func (a *TheAuth) handleStepUp(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	var body struct {
		Method    string          `json:"method"`
		Password  string          `json:"password"`
		Code      string          `json:"code"`
		Challenge string          `json:"challenge"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if !decodeSessionBody(w, r, &body) {
		return
	}
	until, err := a.StepUp(r.Context(), sess, StepUpInput{
		Method: body.Method, Password: body.Password, Code: body.Code,
		Challenge: body.Challenge, Assertion: body.Assertion,
	})
	if err != nil {
		if errors.Is(err, ErrStorageMissingCapability) {
			writeJSONError(w, http.StatusNotImplemented, "not_implemented", "step-up is not supported by this storage")
			return
		}
		errToHTTP(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"elevatedUntil": until})
}

func (a *TheAuth) handleStepUpPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	assertion, challenge, err := a.webauthnSvc.BeginLogin(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": assertion, "challenge": challenge})
}

func (a *TheAuth) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if !decodeSessionBody(w, r, &body) {
		return
	}
	tok, err := a.ChangePassword(r.Context(), *sess, body.CurrentPassword, body.NewPassword)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	a.setSessionCookie(w, tok)
	w.WriteHeader(http.StatusNoContent)
}

func (a *TheAuth) handleSessionLinkConsume(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if !decodeSessionBody(w, r, &body) {
		return
	}
	if body.Token == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "token required")
		return
	}
	tok, _, err := a.ConsumeSessionLink(r.Context(), body.Token, r.UserAgent(), extractClientIPTrusting(r, a.trustedProxies))
	if err != nil {
		if errors.Is(err, ErrSessionLinkInvalid) {
			writeJSONError(w, http.StatusUnauthorized, "session_link_invalid", "invalid or expired session link")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	a.setSessionCookie(w, tok)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
