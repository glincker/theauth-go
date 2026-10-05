package theauth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// mountDevice registers /auth/device/code, /token and /approve. The first two
// are unauthenticated by design (RFC 8628); approve needs a full session.
func (a *TheAuth) mountDevice(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	pollLimit := a.RateLimitByIP(120)
	r.Route("/device", func(r chi.Router) {
		r.With(ipLimit).Post("/code", a.handleDeviceCode)
		r.With(pollLimit).Post("/token", a.handleDeviceToken)
		r.With(a.RequireAuth(), ipLimit).Post("/approve", a.handleDeviceApprove)
	})
}

func writeDeviceError(w http.ResponseWriter, status int, code, desc string) {
	writeTokenJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// readParams accepts a JSON object of strings or form-encoded values, as RFC 8628 clients send forms.
func readParams(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	out := map[string]any{}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
			return nil, false
		}
		return out, true
	}
	if err := r.ParseForm(); err != nil {
		return nil, false
	}
	for k, v := range r.PostForm {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out, true
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func abilitiesParam(m map[string]any) []string {
	switch v := m["scope"].(type) {
	case string:
		return strings.Fields(v)
	}
	var out []string
	if list, ok := m["abilities"].([]any); ok {
		for _, e := range list {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func (a *TheAuth) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if a.apiTokens == nil || a.apiTokens.dev == nil {
		writeDeviceError(w, http.StatusNotFound, "unsupported", "device authorization is not enabled")
		return
	}
	p, ok := readParams(w, r)
	if !ok {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	res, err := a.StartDeviceAuth(r.Context(), StartDeviceAuthInput{
		ClientName: str(p, "client_name"), Abilities: abilitiesParam(p),
		IP: extractClientIPTrusting(r, a.trustedProxies), UserAgent: r.UserAgent(),
	})
	if errors.Is(err, ErrAbilityInvalid) {
		writeDeviceError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}
	if err != nil {
		slog.Error("theauth: device code start failed", "err", err.Error())
		writeDeviceError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	writeTokenJSON(w, http.StatusOK, map[string]any{
		"device_code": res.DeviceCode, "user_code": res.UserCode,
		"verification_uri": res.VerificationURI, "verification_uri_complete": res.VerificationURIComplete,
		"expires_in": int(res.ExpiresIn.Seconds()), "interval": int(res.Interval.Seconds()),
	})
}

func (a *TheAuth) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	if a.apiTokens == nil || a.apiTokens.dev == nil {
		writeDeviceError(w, http.StatusNotFound, "unsupported", "device authorization is not enabled")
		return
	}
	p, ok := readParams(w, r)
	if !ok || str(p, "grant_type") != deviceGrantType || str(p, "device_code") == "" {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "grant_type and device_code are required")
		return
	}
	res, err := a.RedeemDeviceCode(r.Context(), str(p, "device_code"))
	switch {
	case err == nil:
		writeTokenJSON(w, http.StatusOK, map[string]any{
			"access_token": res.Token, "token_type": "Bearer",
			"expires_in": int(res.ExpiresIn.Seconds()), "scope": strings.Join(res.APIToken.Abilities, " "),
		})
	case errors.Is(err, ErrDeviceAuthorizationPending):
		writeDeviceError(w, http.StatusBadRequest, "authorization_pending", "the user has not approved yet")
	case errors.Is(err, ErrDeviceSlowDown):
		writeDeviceError(w, http.StatusBadRequest, "slow_down", "polling too fast")
	case errors.Is(err, ErrDeviceExpired):
		writeDeviceError(w, http.StatusBadRequest, "expired_token", "the device code expired")
	case errors.Is(err, ErrDeviceDenied):
		writeDeviceError(w, http.StatusBadRequest, "access_denied", "the request was denied")
	case errors.Is(err, ErrDeviceInvalid):
		writeDeviceError(w, http.StatusBadRequest, "invalid_grant", "unknown or already used device code")
	default:
		slog.Error("theauth: device token redeem failed", "err", err.Error())
		writeDeviceError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
}

func (a *TheAuth) handleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	if a.apiTokens == nil || a.apiTokens.dev == nil {
		writeDeviceError(w, http.StatusNotFound, "unsupported", "device authorization is not enabled")
		return
	}
	user, _ := UserFromContext(r.Context())
	p, ok := readParams(w, r)
	if !ok {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	ip := extractClientIPTrusting(r, a.trustedProxies)
	code := str(p, "user_code")
	if str(p, "action") == "info" {
		info, err := a.LookupDeviceRequest(r.Context(), user, ip, code)
		if a.writeDeviceDecideError(w, err) {
			return
		}
		writeTokenJSON(w, http.StatusOK, map[string]any{
			"client_name": info.ClientName, "abilities": info.RequestedAbilities,
			"requester_ip": info.RequesterIP, "requester_user_agent": info.RequesterUserAgent, "expires_at": info.ExpiresAt,
		})
		return
	}
	approve := str(p, "action") != "deny"
	err := a.DecideDeviceRequest(r.Context(), user, ip, code, approve, abilitiesParam(p))
	if a.writeDeviceDecideError(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *TheAuth) writeDeviceDecideError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrDeviceAttemptsExceeded):
		w.Header().Set("Retry-After", "900")
		writeDeviceError(w, http.StatusTooManyRequests, "rate_limited", err.Error())
	case errors.Is(err, ErrDeviceInvalid):
		writeDeviceError(w, http.StatusNotFound, "invalid_user_code", "unknown user code")
	case errors.Is(err, ErrDeviceExpired):
		writeDeviceError(w, http.StatusGone, "expired_token", "the request expired")
	case errors.Is(err, ErrAbilityNotHeld):
		writeDeviceError(w, http.StatusForbidden, "ability_not_held", err.Error())
	case errors.Is(err, ErrAbilityInvalid):
		writeDeviceError(w, http.StatusBadRequest, "invalid_scope", err.Error())
	default:
		slog.Error("theauth: device approval failed", "err", err.Error())
		writeDeviceError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
	return true
}
