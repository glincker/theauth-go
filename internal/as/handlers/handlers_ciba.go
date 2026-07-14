package handlers

// handlers_ciba.go: HTTP surface for CIBA (RFC 9509) endpoints.
// POST /oauth/bc-authorize is mounted only when CIBA is enabled.
// The CIBA arm of POST /oauth/token is dispatched from handleToken in
// handlers.go via the GrantTypeCIBA constant.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	internalas "github.com/glincker/theauth-go/internal/as"
	"github.com/glincker/theauth-go/internal/models"
)

// handleBCAuthorize implements POST /oauth/bc-authorize per RFC 9509 section 7.
func (h *Handler) handleBCAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed form")
		return
	}
	clientID, clientSecret := parseClientCredentials(r)
	req := internalas.BackchannelAuthRequest{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		LoginHint:               r.PostFormValue("login_hint"),
		LoginHintToken:          r.PostFormValue("login_hint_token"),
		IDTokenHint:             r.PostFormValue("id_token_hint"),
		Scope:                   scopeSplit(r.PostFormValue("scope")),
		BindingMessage:          r.PostFormValue("binding_message"),
		ClientNotificationToken: r.PostFormValue("client_notification_token"),
	}
	if raw := r.PostFormValue("requested_expiry"); raw != "" {
		var n int
		if err := parseIntField(raw, &n); err == nil && n > 0 {
			req.RequestedExpiry = n
		}
	}
	resp, err := h.svc.BackchannelAuthenticate(r.Context(), req)
	if err != nil {
		writeBCAuthorizeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// writeBCAuthorizeError maps internal CIBA errors to wire error responses for
// /oauth/bc-authorize.
func writeBCAuthorizeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, models.ErrCIBADisabled):
		http.NotFound(w, nil)
	case errors.Is(err, models.ErrOAuthInvalidClient):
		writeOAuthError(w, http.StatusUnauthorized, oauthErrInvalidClient, "client authentication failed")
	case errors.Is(err, models.ErrCIBAInvalidRequest),
		errors.Is(err, models.ErrOAuthInvalidRequest):
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, err.Error())
	case internalas.IsCIBANotifyError(err):
		writeOAuthError(w, http.StatusServiceUnavailable, "service_unavailable", "authentication device notification failed")
	default:
		writeOAuthError(w, http.StatusInternalServerError, oauthErrServerError, err.Error())
	}
}

// writeCIBATokenError maps CIBA token-poll errors to the RFC 9509 wire codes.
func writeCIBATokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, models.ErrCIBAAuthorizationPending):
		writeOAuthError(w, http.StatusBadRequest, "authorization_pending", "user has not yet approved the request")
	case errors.Is(err, models.ErrCIBASlowDown):
		writeOAuthError(w, http.StatusBadRequest, "slow_down", "polling too fast; increase interval")
	case errors.Is(err, models.ErrCIBAAccessDenied):
		writeOAuthError(w, http.StatusBadRequest, "access_denied", "user denied the request")
	case errors.Is(err, models.ErrCIBAExpiredToken):
		writeOAuthError(w, http.StatusBadRequest, "expired_token", "auth_req_id has expired")
	case errors.Is(err, models.ErrCIBAInvalidRequest),
		errors.Is(err, models.ErrOAuthInvalidRequest):
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, err.Error())
	case errors.Is(err, models.ErrOAuthInvalidGrant):
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidGrant, "invalid auth_req_id")
	case errors.Is(err, models.ErrOAuthInvalidClient):
		writeOAuthError(w, http.StatusUnauthorized, oauthErrInvalidClient, "client authentication failed")
	case errors.Is(err, models.ErrOAuthUnsupportedGrantType):
		writeOAuthError(w, http.StatusBadRequest, oauthErrUnsupportedGrantType, "CIBA not enabled")
	default:
		writeOAuthError(w, http.StatusInternalServerError, oauthErrServerError, err.Error())
	}
}

// parseIntField parses a decimal integer string into n. Returns an error for
// empty or non-numeric input.
func parseIntField(s string, n *int) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("empty")
	}
	v := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return errors.New("non-numeric")
		}
		v = v*10 + int(ch-'0')
	}
	*n = v
	return nil
}
