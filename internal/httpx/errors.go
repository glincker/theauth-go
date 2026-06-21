// Package httpx hosts shared HTTP helpers used by extracted handler
// packages: the canonical sentinel-error to status mapping, the
// {code,message} JSON error body, the URL-param ULID parser, and the
// no-trust client IP shim. Extracted from root handlers.go in PR E of
// the 2026-06 architecture reorg so internal handler packages do not
// each re-implement these.
package httpx

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/glincker/theauth-go/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"
)

// ErrToHTTP maps any error a service layer returns to the canonical
// HTTP status the legacy root handlers emitted. Mirrors the root
// errToHTTP behavior verbatim so the public surface is unchanged.
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
		case models.CodeRateLimited:
			WriteJSONError(w, http.StatusTooManyRequests, te.Code, te.Message)
		case models.CodePasswordResetExpired, models.CodePasswordResetInvalid:
			WriteJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		case models.CodeInvalidTOTP, models.CodeWebAuthn:
			WriteJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		case models.CodeAlreadyEnrolled:
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
		http.Error(w, err.Error(), http.StatusUnauthorized)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
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

// ParseULIDParam parses a Crockford-base32 ULID from a URL path
// parameter. Returns an error on any malformed input; callers map that
// to 400.
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

// PathULID parses a chi URL path parameter into a ULID. On parse
// failure it writes a 400 plain-text response and returns ok=false.
// Mirrors the legacy root pathULID exactly.
func PathULID(w http.ResponseWriter, r *http.Request, name string) (models.ULID, bool) {
	raw := chi.URLParam(r, name)
	id, err := ulid.Parse(raw)
	if err != nil {
		http.Error(w, "invalid "+name, http.StatusBadRequest)
		return models.ULID{}, false
	}
	return id, true
}

// ParseULIDPath is the silent variant of PathULID: it does not write a
// response on failure, leaving the caller free to emit a structured
// problem+json body. Mirrors the legacy root parseULIDPath.
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
