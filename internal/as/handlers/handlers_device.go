package handlers

// handlers_device.go: HTTP surface for the RFC 8628 device grant.
//
//	POST /oauth/device_authorization   start (rate limited)
//	GET  /oauth/device                 verification page (HTML) or lookup (JSON)
//	POST /oauth/device                 confirm or decide (form or JSON)
//
// The device_code arm of POST /oauth/token lives in handlers.go.

import (
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/go-chi/chi/v5"
)

const (
	devicePath          = "/oauth/device"
	maxDeviceFormBytes  = 1 << 12
	deviceActionLookup  = "lookup"
	deviceActionApprove = "approve"
	deviceActionDeny    = "deny"
)

func (h *Handler) mountDevice(r chi.Router, authn func(http.Handler) http.Handler) {
	r.With(h.limited).Post("/oauth/device_authorization", h.handleDeviceAuthorization)
	r.With(authn).Get(devicePath, h.handleDevicePage)
	r.With(authn).Post(devicePath, h.handleDeviceDecision)
}

// handleDeviceAuthorization implements RFC 8628 section 3.1 and 3.2.
func (h *Handler) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLimitedBody)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed form")
		return
	}
	clientID, clientSecret := parseClientCredentials(r)
	resp, err := h.svc.StartDeviceAuthorization(r.Context(), internalas.DeviceAuthRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scopeSplit(r.PostFormValue("scope")),
		Resource:     r.PostFormValue("resource"),
	})
	if err != nil {
		switch {
		case isBusy(err):
			writeBusy(w)
		case errors.Is(err, models.ErrDeviceAuthDisabled):
			http.NotFound(w, r)
		case errors.Is(err, models.ErrOAuthInvalidClient):
			writeOAuthError(w, http.StatusUnauthorized, oauthErrInvalidClient, "client authentication failed")
		case errors.Is(err, models.ErrOAuthUnsupportedGrantType):
			writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "client is not registered for the device_code grant")
		case errors.Is(err, models.ErrOAuthInvalidScope):
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidScope, "invalid or missing scope")
		case errors.Is(err, models.ErrOAuthInvalidResource):
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidTarget, "invalid or missing resource")
		default:
			slog.Error("theauth: device authorization failed", "err", err.Error())
			writeOAuthError(w, http.StatusInternalServerError, oauthErrServerError, "could not start device authorization")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// writeDeviceTokenError maps device_code poll errors to RFC 8628 section 3.5.
func (h *Handler) writeDeviceTokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, models.ErrDeviceAuthorizationPending):
		writeOAuthError(w, http.StatusBadRequest, "authorization_pending", "the user has not finished authorizing")
	case errors.Is(err, models.ErrDeviceSlowDown):
		writeOAuthError(w, http.StatusBadRequest, "slow_down", "polling too fast, increase the interval by 5 seconds")
	case errors.Is(err, models.ErrDeviceAccessDenied):
		writeOAuthError(w, http.StatusBadRequest, oauthErrAccessDenied, "the user denied the request")
	case errors.Is(err, models.ErrDeviceExpiredToken):
		writeOAuthError(w, http.StatusBadRequest, "expired_token", "the device_code has expired")
	default:
		h.writeTokenErrorDPoP(w, err)
	}
}

// ---------- verification page ----------

func wantsJSON(r *http.Request) bool {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func (h *Handler) deviceSubject(r *http.Request) (*models.User, string) {
	user, _ := h.userFromCtx(r)
	if user == nil {
		return nil, ""
	}
	return user, "user:" + user.ID.String()
}

// requireUser answers anonymous visitors: JSON callers get 401, browsers are
// sent to sign in and back.
func (h *Handler) requireUser(w http.ResponseWriter, r *http.Request) (*models.User, string, bool) {
	user, subject := h.deviceSubject(r)
	if user != nil {
		return user, subject, true
	}
	if wantsJSON(r) {
		writeOAuthError(w, http.StatusUnauthorized, "login_required", "sign in first")
		return nil, "", false
	}
	next := url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, h.svc.Cfg.LoginURL+"?next="+next, http.StatusFound)
	return nil, "", false
}

func (h *Handler) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	if _, subject, ok := h.requireUser(w, r); ok {
		code := r.URL.Query().Get("user_code")
		if code == "" {
			h.renderDevice(w, r, http.StatusOK, internalas.DevicePage{State: internalas.DevicePageEnter})
			return
		}
		h.lookupAndRender(w, r, subject, code)
	}
}

func (h *Handler) lookupAndRender(w http.ResponseWriter, r *http.Request, subject, code string) {
	pending, err := h.svc.LookupDeviceUserCode(r.Context(), subject, code)
	if err != nil {
		h.deviceError(w, r, err)
		return
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{
			"client_id":   pending.ClientID,
			"client_name": pending.ClientName,
			"scope":       strings.Join(pending.Scope, " "),
			"expires_at":  pending.ExpiresAt,
		})
		return
	}
	h.renderDevice(w, r, http.StatusOK, internalas.DevicePage{
		State: internalas.DevicePageConfirm, UserCode: code, Pending: &pending,
	})
}

// deviceRequest is the JSON body of POST /oauth/device.
type deviceRequest struct {
	UserCode string `json:"user_code"`
	Action   string `json:"action"`
}

func readDeviceRequest(w http.ResponseWriter, r *http.Request) (deviceRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxDeviceFormBytes)
	var req deviceRequest
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		b, err := io.ReadAll(r.Body)
		if err != nil || json.Unmarshal(b, &req) != nil {
			return req, false
		}
		return req, true
	}
	if err := r.ParseForm(); err != nil {
		return req, false
	}
	return deviceRequest{UserCode: r.PostFormValue("user_code"), Action: r.PostFormValue("action")}, true
}

func (h *Handler) handleDeviceDecision(w http.ResponseWriter, r *http.Request) {
	user, subject, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	req, ok := readDeviceRequest(w, r)
	if !ok || req.UserCode == "" {
		h.deviceError(w, r, models.ErrDeviceUserCodeInvalid)
		return
	}
	switch req.Action {
	case "", deviceActionLookup:
		h.lookupAndRender(w, r, subject, req.UserCode)
	case deviceActionApprove, deviceActionDeny:
		approve := req.Action == deviceActionApprove
		if err := h.svc.DecideDeviceUserCode(r.Context(), subject, req.UserCode, user.ID, approve); err != nil {
			h.deviceError(w, r, err)
			return
		}
		status := "denied"
		if approve {
			status = "approved"
		}
		if wantsJSON(r) {
			writeJSON(w, http.StatusOK, map[string]string{"status": status})
			return
		}
		h.renderDevice(w, r, http.StatusOK, internalas.DevicePage{State: internalas.DevicePageDone, Approved: approve})
	default:
		h.deviceError(w, r, models.ErrDeviceUserCodeInvalid)
	}
}

func (h *Handler) deviceError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, msg := http.StatusInternalServerError, "server_error", "something went wrong"
	switch {
	case errors.Is(err, models.ErrDeviceUserCodeInvalid):
		status, code, msg = http.StatusBadRequest, "invalid_user_code", "That code is not valid or has expired."
	case errors.Is(err, models.ErrDeviceTooManyAttempts):
		status, code, msg = http.StatusTooManyRequests, "too_many_attempts", "Too many attempts. Wait a few minutes and try again."
		w.Header().Set("Retry-After", "60")
	default:
		slog.Error("theauth: device verification failed", "err", err.Error())
	}
	if wantsJSON(r) {
		writeJSON(w, status, map[string]string{"error": code, "error_description": msg})
		return
	}
	state := internalas.DevicePageEnter
	if status >= 500 {
		state = internalas.DevicePageError
	}
	h.renderDevice(w, r, status, internalas.DevicePage{State: state, Error: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) renderDevice(w http.ResponseWriter, r *http.Request, status int, p internalas.DevicePage) {
	cfg := h.svc.Cfg.DeviceAuthorization
	p.Action = devicePath
	p.CSS = cfg.CSS
	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Referrer-Policy", "no-referrer")
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("X-Frame-Options", "DENY")
	// The page is one self-contained document: no scripts, no framing, forms
	// only to this origin. Custom renderers may replace these headers.
	hdr.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if cfg.Page != nil {
		w.WriteHeader(status)
		cfg.Page(w, r, p)
		return
	}
	w.WriteHeader(status)
	if err := devicePageTmpl.Execute(w, struct {
		internalas.DevicePage
		CSSText template.CSS
	}{p, template.CSS(p.CSS)}); err != nil {
		slog.Error("theauth: device page render failed", "err", err.Error())
	}
}

// defaultDeviceCSS is deliberately plain. Every color is a custom property so
// a theme only needs to override a few variables.
const defaultDeviceCSS = `:root{--bg:#fff;--fg:#111;--muted:#555;--accent:#1d4ed8;--danger:#b91c1c;--border:#d4d4d8}
@media (prefers-color-scheme:dark){:root{--bg:#111;--fg:#f4f4f5;--muted:#a1a1aa;--accent:#60a5fa;--danger:#f87171;--border:#3f3f46}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:28rem;margin:10vh auto;padding:0 1rem}
input[type=text]{width:100%;box-sizing:border-box;font:inherit;font-size:1.5rem;letter-spacing:.15em;text-transform:uppercase;padding:.5rem;border:1px solid var(--border);background:transparent;color:inherit}
button{font:inherit;padding:.5rem 1rem;border:1px solid var(--border);background:transparent;color:inherit;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.error{color:var(--danger)}.muted{color:var(--muted)}`

var devicePageTmpl = template.Must(template.New("device").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect a device</title>
<style>` + defaultDeviceCSS + `{{.CSSText}}</style></head>
<body><main data-state="{{.State}}">
{{if eq .State "enter"}}
<h1>Connect a device</h1>
<p class="muted">Enter the code shown on your device.</p>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
<input type="hidden" name="action" value="lookup">
<label for="user_code">Code</label>
<input id="user_code" name="user_code" type="text" autocomplete="off" autocapitalize="characters" spellcheck="false" required autofocus>
<p><button class="primary" type="submit">Continue</button></p>
</form>
{{else if eq .State "confirm"}}
<h1>Allow access?</h1>
<p><strong>{{.Pending.ClientName}}</strong> wants to act on your behalf.</p>
{{if .Pending.Scope}}<p class="muted">Permissions: {{range $i, $s := .Pending.Scope}}{{if $i}}, {{end}}{{$s}}{{end}}</p>{{end}}
<p class="muted">Code: <code>{{.UserCode}}</code>. Only continue if this matches your device.</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="user_code" value="{{.UserCode}}">
<button class="primary" type="submit" name="action" value="approve">Allow</button>
<button type="submit" name="action" value="deny">Deny</button>
</form>
{{else if eq .State "done"}}
{{if .Approved}}<h1>Device connected</h1><p>You can return to your device.</p>
{{else}}<h1>Request denied</h1><p>Nothing was shared with the device.</p>{{end}}
{{else}}
<h1>Something went wrong</h1><p class="error" role="alert">{{.Error}}</p>
{{end}}
</main></body></html>`))
