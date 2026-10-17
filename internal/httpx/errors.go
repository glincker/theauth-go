// Package httpx holds shared HTTP helpers for the extracted handler packages: the error to status
// mapping, the {code,message} body, the ULID path parser and the client IP shim.
package httpx

import (
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"
)

// ErrToHTTP maps a service error to its canonical HTTP status, matching the legacy root behavior.
func ErrToHTTP(w http.ResponseWriter, err error) {
	var te *models.TheAuthError
	if errors.As(err, &te) {
		switch te.Code {
		case models.CodeWeakPassword:
			WriteJSONError(w, http.StatusBadRequest, te.Code, te.Message)
		case models.CodeEmailTaken:
			WriteJSONError(w, http.StatusConflict, te.Code, te.Message)
		case models.CodeInvalidCredentials:
			WriteJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		case models.CodeRateLimited, models.CodeAccountLocked:
			if te.RetryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(te.RetryAfter.Seconds()))))
			}
			WriteJSONError(w, http.StatusTooManyRequests, te.Code, te.Message)
		case models.CodeSignupClosed, models.CodeSetupTokenInvalid:
			WriteJSONError(w, http.StatusForbidden, te.Code, te.Message)
		case models.CodePasswordResetExpired, models.CodePasswordResetInvalid:
			WriteJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		case models.CodeInvalidTOTP, models.CodeWebAuthn:
			WriteJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		case models.CodeAlreadyEnrolled:
			WriteJSONError(w, http.StatusConflict, te.Code, te.Message)
		case models.CodePasswordChangeRequired, models.CodeAccountDisabled, models.CodeReauthRequired:
			WriteJSONError(w, http.StatusForbidden, te.Code, te.Message)
		case models.CodeSessionLimit:
			WriteJSONError(w, http.StatusConflict, te.Code, te.Message)
		case models.CodeTOTPRequired:
			WriteJSONError(w, http.StatusOK, te.Code, te.Message)
		default:
			WriteJSONError(w, http.StatusInternalServerError, te.Code, "internal error")
		}
		return
	}
	switch {
	case errors.Is(err, models.ErrInvalidToken),
		errors.Is(err, models.ErrMagicLinkExpired),
		errors.Is(err, models.ErrSessionExpired):
		Error(w, http.StatusUnauthorized, err.Error())
	default:
		Error(w, http.StatusInternalServerError, "internal error")
	}
}

// Error writes a JSON error body whose stable code derives from the HTTP
// status. Replaces plain-text http.Error across the handlers.
func Error(w http.ResponseWriter, status int, message string) {
	WriteJSONError(w, status, codeForStatus(status), message)
}

func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return models.CodeBadRequest
	case http.StatusUnauthorized:
		return models.CodeUnauthorized
	case http.StatusForbidden:
		return models.CodeForbidden
	case http.StatusNotFound:
		return models.CodeNotFound
	case http.StatusConflict:
		return models.CodeConflict
	case http.StatusTooManyRequests:
		return models.CodeRateLimited
	default:
		return models.CodeInternal
	}
}

// WriteJSONError emits the v0.2+ {"code":...,"message":...} body.
func WriteJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message})
}

// ParseULIDParam parses a Crockford base32 ULID from a path parameter. Callers map an error to 400.
func ParseULIDParam(s string) (models.ULID, error) {
	return ulid.Parse(s)
}

// ClientIP returns the connection-level remote host (port stripped),
// ignoring X-Forwarded-For. Matches the legacy root extractClientIP.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// WriteJSON marshals v as a JSON body with status. Used by every
// extracted handler package; identical to the legacy root writeJSON.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// PathULID parses a chi path parameter as a ULID. On failure it writes a 400 and returns ok=false.
func PathULID(w http.ResponseWriter, r *http.Request, name string) (models.ULID, bool) {
	raw := chi.URLParam(r, name)
	id, err := ulid.Parse(raw)
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid "+name)
		return models.ULID{}, false
	}
	return id, true
}

// ParseULIDPath is the silent PathULID, which leaves the response to the caller.
func ParseULIDPath(r *http.Request, name string) (models.ULID, bool) {
	s := chi.URLParam(r, name)
	if s == "" {
		return models.ULID{}, false
	}
	id, err := ulid.Parse(s)
	if err != nil {
		return models.ULID{}, false
	}
	return id, true
}

// DecodeJSON decodes the request body into v, capping the read at 64
// KiB to prevent memory DoS. Mirrors the legacy root decodeJSON.
func DecodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<16)
	return json.NewDecoder(r.Body).Decode(v)
}
