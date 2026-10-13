package mcpresource

import (
	"encoding/json"
	"net/http"
)

// Denial is the machine readable JSON body written with 401 and 403
// responses. The matching WWW-Authenticate header (RFC 6750, RFC 9470) is
// the normative signal; the body lets clients and agents branch on the same
// facts without parsing the header.
type Denial struct {
	// Error is the OAuth error code (invalid_token, insufficient_scope,
	// insufficient_user_authentication, ...).
	Error string `json:"error"`
	// ErrorDescription is a human readable explanation.
	ErrorDescription string `json:"error_description,omitempty"`
	// RequiredScopes lists the scopes the resource needs (insufficient_scope).
	RequiredScopes []string `json:"required_scopes,omitempty"`
	// ResourceMetadata is the RFC 9728 protected resource metadata URL.
	ResourceMetadata string `json:"resource_metadata,omitempty"`
	// StepUp is present when the client must re-authenticate (RFC 9470).
	StepUp *StepUpHint `json:"step_up,omitempty"`
}

// StepUpHint carries the RFC 9470 authentication requirements: the acceptable
// acr values and the maximum authentication age in seconds.
type StepUpHint struct {
	ACRValues []string `json:"acr_values,omitempty"`
	MaxAge    int64    `json:"max_age,omitempty"`
}

// WriteDenial writes d as the JSON body of a denial response with the given
// status (normally 401 or 403). It sets Content-Type and Cache-Control but
// not WWW-Authenticate; callers set that header first so the status line and
// header stay under their control.
func WriteDenial(w http.ResponseWriter, status int, d Denial) {
	body, err := json.Marshal(d)
	if err != nil {
		// Denial holds only strings and ints, so this cannot happen; fall
		// back to the bare error code rather than an empty body.
		body = []byte(`{"error":"server_error"}`)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// challenge builds a WWW-Authenticate value for scheme with the supplied
// error and optional auth-params. Params with empty values are skipped.
func challenge(scheme, errCode, description string, params ...[2]string) string {
	value := scheme + ` error="` + errCode + `"`
	if description != "" {
		value += `, error_description="` + escapeQuoted(description) + `"`
	}
	for _, p := range params {
		if p[1] != "" {
			value += ", " + p[0] + `="` + escapeQuoted(p[1]) + `"`
		}
	}
	return value
}
