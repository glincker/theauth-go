package handlers

// handlers_device_identity.go serves constrained device enrollment (challenge and enroll) and its
// org-scoped admin routes.

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/v2/admin"
	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/go-chi/chi/v5"
)

type enrollBody struct {
	Kind      string          `json:"kind"`
	JoinToken string          `json:"join_token"`
	JWK       json.RawMessage `json:"jwk"`
	Challenge string          `json:"challenge"`
	Proof     string          `json:"proof"`
	Name      string          `json:"name"`
}

func (b enrollBody) request() internalas.DeviceEnrollRequest {
	return internalas.DeviceEnrollRequest{
		Kind: b.Kind, JoinToken: b.JoinToken, JWK: b.JWK, Challenge: b.Challenge, Proof: b.Proof, Name: b.Name,
	}
}

func (h *Handler) mountDeviceIdentity(r chi.Router) {
	r.With(h.limited).Post("/oauth/devices/challenge", h.handleDeviceChallenge)
	r.With(h.limited).Post("/oauth/devices/enroll", h.handleDeviceEnroll)
}

func (h *Handler) writeEnrollError(w http.ResponseWriter, err error) {
	var limited *internalas.RateLimitedError
	if errors.As(err, &limited) {
		writeRateLimited(w, limited.RetryAfter)
		return
	}
	switch {
	case errors.Is(err, models.ErrDeviceEnrollmentInvalid):
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidGrant, "invalid join token, key or proof")
	case errors.Is(err, models.ErrDeviceConflict):
		writeOAuthError(w, http.StatusConflict, oauthErrInvalidRequest, "device identity already registered")
	default:
		writeOAuthError(w, http.StatusInternalServerError, oauthErrServerError, err.Error())
	}
}

func (h *Handler) handleDeviceChallenge(w http.ResponseWriter, r *http.Request) {
	var body enrollBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed body")
		return
	}
	ch, err := h.svc.DeviceEnrollChallenge(r.Context(), body.request())
	if err != nil {
		h.writeEnrollError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ch)
}

func (h *Handler) handleDeviceEnroll(w http.ResponseWriter, r *http.Request) {
	var body enrollBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed body")
		return
	}
	d, err := h.svc.EnrollDevice(r.Context(), body.request())
	if err != nil {
		h.writeEnrollError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"device_id": d.ID.String(), "name": d.Name, "subject": d.Subject(), "spiffe_id": d.SPIFFEID, "scope": d.Scopes,
	})
}

// deviceView is the wire form of a device. It carries only the public thumbprint, never key material.
type deviceView struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	SPIFFEID    string     `json:"spiffe_id,omitempty"`
	Subject     string     `json:"subject"`
	Attestation string     `json:"attestation"`
	Thumbprint  string     `json:"key_thumbprint"`
	Scopes      []string   `json:"scopes"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

func deviceViewOf(d models.Device) deviceView {
	scopes := d.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	return deviceView{
		ID: d.ID.String(), Name: d.Name, SPIFFEID: d.SPIFFEID, Subject: d.Subject(), Attestation: d.Attestation,
		Thumbprint: d.KeyThumbprint, Scopes: scopes, Status: d.Status, CreatedAt: d.CreatedAt,
		LastSeenAt: d.LastSeenAt, RevokedAt: d.RevokedAt,
	}
}

func (a *AdminHandler) mountDevices(r chi.Router, perm func(http.Handler) http.Handler) {
	if !a.svc.DeviceTokensEnabled() {
		return
	}
	r.With(perm).Post("/devices/join-tokens", a.createJoinToken)
	r.With(perm).Delete("/devices/join-tokens/{tokenID}", a.revokeJoinToken)
	r.With(perm).Get("/devices", a.listDevices)
	r.With(perm).Post("/devices/{deviceID}/revoke", a.revokeDevice)
}

func (a *AdminHandler) createJoinToken(w http.ResponseWriter, r *http.Request) {
	orgID, ok := httpx.ParseULIDPath(r, "orgID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid orgID", "")
		return
	}
	var body struct {
		Name       string   `json:"name"`
		SPIFFEID   string   `json:"spiffe_id"`
		Scopes     []string `json:"scopes"`
		TTLSeconds int      `json:"ttl_seconds"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	in := internalas.CreateDeviceJoinTokenInput{
		OrganizationID: &orgID, Name: body.Name, SPIFFEID: body.SPIFFEID, Scopes: body.Scopes,
		TTL: time.Duration(body.TTLSeconds) * time.Second,
	}
	if u, _ := a.userFromCtx(r); u != nil {
		id := u.ID
		in.CreatedBy = &id
	}
	t, raw, err := a.svc.CreateDeviceJoinToken(r.Context(), in)
	if err != nil {
		if errors.Is(err, models.ErrOAuthInvalidRequest) {
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "scopes are required and ttl_seconds must not be negative", "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, "could not create join token", "")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": t.ID.String(), "token": raw, "prefix": t.Prefix, "name": t.Name, "spiffe_id": t.SPIFFEID,
		"scopes": t.Scopes, "expires_at": t.ExpiresAt,
	})
}

func (a *AdminHandler) revokeJoinToken(w http.ResponseWriter, r *http.Request) {
	orgID, ok := httpx.ParseULIDPath(r, "orgID")
	id, ok2 := httpx.ParseULIDPath(r, "tokenID")
	if !ok || !ok2 {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid id", "")
		return
	}
	if err := a.svc.RevokeDeviceJoinToken(r.Context(), id, &orgID); err != nil {
		a.writeDeviceAdminError(w, err, "join token")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *AdminHandler) listDevices(w http.ResponseWriter, r *http.Request) {
	orgID, ok := httpx.ParseULIDPath(r, "orgID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid orgID", "")
		return
	}
	rows, err := a.svc.ListDevices(r.Context(), &orgID)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, "could not list devices", "")
		return
	}
	out := make([]deviceView, 0, len(rows))
	for _, d := range rows {
		out = append(out, deviceViewOf(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (a *AdminHandler) revokeDevice(w http.ResponseWriter, r *http.Request) {
	orgID, ok := httpx.ParseULIDPath(r, "orgID")
	id, ok2 := httpx.ParseULIDPath(r, "deviceID")
	if !ok || !ok2 {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid id", "")
		return
	}
	var actor *models.ULID
	if u, _ := a.userFromCtx(r); u != nil {
		uid := u.ID
		actor = &uid
	}
	if err := a.svc.RevokeDevice(r.Context(), id, &orgID, actor); err != nil {
		a.writeDeviceAdminError(w, err, "device")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *AdminHandler) writeDeviceAdminError(w http.ResponseWriter, err error, what string) {
	if errors.Is(err, models.ErrStorageNotFound) {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, what+" not found", "")
		return
	}
	admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, "could not revoke "+what, "")
}
