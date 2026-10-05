package apitokens

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/go-chi/chi/v5"
	oulid "github.com/oklog/ulid/v2"
)

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// mountDevice registers /auth/device/code, /token and /approve. The first two
// are unauthenticated by design (RFC 8628); approve needs a full session.
func (s *Service) MountDevice(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	pollLimit := s.host.RateLimitByIP(120)
	r.Route("/device", func(r chi.Router) {
		r.With(ipLimit).Post("/code", s.handleDeviceCode)
		r.With(pollLimit).Post("/token", s.handleDeviceToken)
		r.With(s.host.RequireAuth(), ipLimit).Post("/approve", s.handleDeviceApprove)
		r.With(s.host.RequireAuth(), s.requireDeviceReviewer(), ipLimit).Get("/requests", s.handleDeviceRequests)
		r.With(s.host.RequireAuth(), s.requireDeviceReviewer(), ipLimit).Post("/requests/{id}/approve", s.handleDeviceRequestDecide(true))
		r.With(s.host.RequireAuth(), s.requireDeviceReviewer(), ipLimit).Post("/requests/{id}/deny", s.handleDeviceRequestDecide(false))
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

func (s *Service) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if s.dev == nil {
		writeDeviceError(w, http.StatusNotFound, "unsupported", "device authorization is not enabled")
		return
	}
	p, ok := readParams(w, r)
	if !ok {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	res, err := s.StartDeviceAuth(r.Context(), StartDeviceAuthInput{
		ClientName: str(p, "client_name"), Abilities: abilitiesParam(p),
		IP: s.host.ClientIP(r), UserAgent: r.UserAgent(),
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

func (s *Service) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	if s.dev == nil {
		writeDeviceError(w, http.StatusNotFound, "unsupported", "device authorization is not enabled")
		return
	}
	p, ok := readParams(w, r)
	if !ok || str(p, "grant_type") != deviceGrantType || str(p, "device_code") == "" {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "grant_type and device_code are required")
		return
	}
	res, err := s.RedeemDeviceCode(r.Context(), str(p, "device_code"))
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

func (s *Service) handleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	if s.dev == nil {
		writeDeviceError(w, http.StatusNotFound, "unsupported", "device authorization is not enabled")
		return
	}
	user, _ := s.host.UserFromContext(r.Context())
	p, ok := readParams(w, r)
	if !ok {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	ip := s.host.ClientIP(r)
	code := str(p, "user_code")
	if str(p, "action") == "info" {
		info, err := s.LookupDeviceRequest(r.Context(), user, ip, code)
		if s.writeDeviceDecideError(w, err) {
			return
		}
		writeTokenJSON(w, http.StatusOK, map[string]any{
			"client_name": info.ClientName, "abilities": info.RequestedAbilities,
			"requester_ip": info.RequesterIP, "requester_user_agent": info.RequesterUserAgent, "expires_at": info.ExpiresAt,
		})
		return
	}
	approve := str(p, "action") != "deny"
	err := s.DecideDeviceRequest(r.Context(), user, ip, code, approve, abilitiesParam(p))
	if s.writeDeviceDecideError(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) writeDeviceDecideError(w http.ResponseWriter, err error) bool {
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

func (s *Service) handleDeviceRequests(w http.ResponseWriter, r *http.Request) {
	if s.dev == nil {
		writeDeviceError(w, http.StatusNotFound, "unsupported", "device authorization is not enabled")
		return
	}
	list, err := s.ListDeviceRequests(r.Context())
	if errors.Is(err, ErrDeviceListUnsupported) {
		writeDeviceError(w, http.StatusNotFound, "unsupported", "pending request listing is not supported by this storage")
		return
	}
	if err != nil {
		slog.Error("theauth: device request list failed", "err", err.Error())
		writeDeviceError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	writeTokenJSON(w, http.StatusOK, map[string]any{"requests": list})
}

func (s *Service) handleDeviceRequestDecide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.dev == nil {
			writeDeviceError(w, http.StatusNotFound, "unsupported", "device authorization is not enabled")
			return
		}
		id, err := oulid.ParseStrict(chi.URLParam(r, "id"))
		if err != nil {
			writeDeviceError(w, http.StatusNotFound, "invalid_request_id", "unknown request")
			return
		}
		user, _ := s.host.UserFromContext(r.Context())
		var abilities []string
		if approve && r.ContentLength != 0 {
			p, ok := readParams(w, r)
			if !ok {
				writeDeviceError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
				return
			}
			abilities = abilitiesParam(p)
		}
		err = s.DecideDeviceRequestByID(r.Context(), user, id, approve, abilities)
		if errors.Is(err, ErrDeviceListUnsupported) {
			writeDeviceError(w, http.StatusNotFound, "unsupported", "pending request listing is not supported by this storage")
			return
		}
		if s.writeDeviceDecideError(w, err) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Service) requireDeviceReviewer() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.cfg.DeviceRequestsAnySignedInUser {
				next.ServeHTTP(w, r)
				return
			}
			user, ok := s.host.UserFromContext(r.Context())
			if !ok {
				httpx.WriteUnauthenticated(w, "auth.unauthenticated", "Missing or invalid session")
				return
			}
			held, err := s.UserAbilities(r.Context(), user)
			if err != nil {
				slog.Error("theauth: resolve device reviewer abilities failed", "err", err.Error())
				httpx.WriteProblemJSON(w, http.StatusInternalServerError, "auth.internal_error", "Authentication failed", "")
				return
			}
			need := s.cfg.DeviceRequestsAbility
			if need == "" {
				need = AbilityRoot
			}
			if !holdsAbility(held, need) {
				httpx.WriteProblemJSON(w, http.StatusForbidden, "auth.forbidden", "Missing required ability: "+need, "")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
