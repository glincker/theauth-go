package handlers

// handlers_admin_registration.go: admin API for initial access tokens, mounted
// inside the organization-scoped admin tree:
//
//	POST   /admin/v1/organizations/{orgID}/registration-tokens
//	GET    /admin/v1/organizations/{orgID}/registration-tokens
//	DELETE /admin/v1/organizations/{orgID}/registration-tokens/{tokenID}
//
// The plaintext token appears once, in the POST response.

import (
	"errors"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/v2/admin"
	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/go-chi/chi/v5"
)

// AdminHandler serves the registration-token admin routes.
type AdminHandler struct {
	svc         *internalas.Service
	userFromCtx func(r *http.Request) (*models.User, bool)
}

// NewAdmin constructs an AdminHandler.
func NewAdmin(svc *internalas.Service, userFromCtx func(r *http.Request) (*models.User, bool)) *AdminHandler {
	return &AdminHandler{svc: svc, userFromCtx: userFromCtx}
}

// Mount attaches the routes to an org-scoped router. gate returns the
// permission middleware (root passes RequirePermission).
func (a *AdminHandler) Mount(r chi.Router, gate func(permission string) func(http.Handler) http.Handler) {
	if !a.svc.RegistrationTokensEnabled() {
		return
	}
	perm := gate(models.PermissionAgentsAdmin)
	r.With(perm).Post("/registration-tokens", a.create)
	r.With(perm).Get("/registration-tokens", a.list)
	r.With(perm).Delete("/registration-tokens/{tokenID}", a.revoke)
}

// registrationTokenView is the wire form of a token. It never carries the
// hash.
type registrationTokenView struct {
	ID         string     `json:"id"`
	Prefix     string     `json:"prefix"`
	Label      string     `json:"label"`
	Scopes     []string   `json:"scopes"`
	GrantTypes []string   `json:"grant_types"`
	MaxUses    int        `json:"max_uses"`
	Uses       int        `json:"uses"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Active     bool       `json:"active"`
}

func viewOf(t models.RegistrationToken, now time.Time) registrationTokenView {
	scopes, grants := t.Scopes, t.GrantTypes
	if scopes == nil {
		scopes = []string{}
	}
	if grants == nil {
		grants = []string{}
	}
	return registrationTokenView{
		ID: t.ID.String(), Prefix: t.Prefix, Label: t.Label, Scopes: scopes, GrantTypes: grants,
		MaxUses: t.MaxUses, Uses: t.Uses, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt, Active: t.Active(now),
	}
}

func (a *AdminHandler) create(w http.ResponseWriter, r *http.Request) {
	orgID, ok := httpx.ParseULIDPath(r, "orgID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid orgID", "")
		return
	}
	var body struct {
		Label      string   `json:"label"`
		Scopes     []string `json:"scopes"`
		GrantTypes []string `json:"grant_types"`
		MaxUses    int      `json:"max_uses"`
		TTLSeconds int      `json:"ttl_seconds"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	in := internalas.CreateRegistrationTokenInput{
		Label:          body.Label,
		OrganizationID: &orgID,
		Scopes:         body.Scopes,
		GrantTypes:     body.GrantTypes,
		MaxUses:        body.MaxUses,
		TTL:            time.Duration(body.TTLSeconds) * time.Second,
	}
	if u, _ := a.userFromCtx(r); u != nil {
		id := u.ID
		in.CreatedBy = &id
	}
	t, raw, err := a.svc.CreateRegistrationToken(r.Context(), in)
	if err != nil {
		if errors.Is(err, models.ErrOAuthInvalidRequest) {
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid max_uses, ttl_seconds or grant_types", "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, "could not create token", "")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, struct {
		registrationTokenView
		Token string `json:"token"`
	}{viewOf(t, time.Now()), raw})
}

func (a *AdminHandler) list(w http.ResponseWriter, r *http.Request) {
	orgID, ok := httpx.ParseULIDPath(r, "orgID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid orgID", "")
		return
	}
	rows, err := a.svc.ListRegistrationTokens(r.Context(), &orgID)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, "could not list tokens", "")
		return
	}
	now := time.Now()
	out := make([]registrationTokenView, 0, len(rows))
	for _, t := range rows {
		out = append(out, viewOf(t, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (a *AdminHandler) revoke(w http.ResponseWriter, r *http.Request) {
	orgID, ok := httpx.ParseULIDPath(r, "orgID")
	id, ok2 := httpx.ParseULIDPath(r, "tokenID")
	if !ok || !ok2 {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid id", "")
		return
	}
	var actor *models.ULID
	if u, _ := a.userFromCtx(r); u != nil {
		uid := u.ID
		actor = &uid
	}
	if err := a.svc.RevokeRegistrationToken(r.Context(), id, &orgID, actor); err != nil {
		if errors.Is(err, models.ErrStorageNotFound) {
			admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "token not found", "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, "could not revoke token", "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
