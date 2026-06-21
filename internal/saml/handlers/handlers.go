// Package handlers exposes the SAML SP-flow endpoints
// (/auth/saml/{connectionId}/login, /acs, /metadata).
//
// Extracted from root handlers_saml.go in PR E of the 2026-06
// architecture reorg. The SP-flow lives here; the per-organization
// connection CRUD endpoints (mounted under
// /auth/orgs/{orgId}/saml/connections) stay in root because they
// depend on the unextracted requireOrgRole helper.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/internal/httpx"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/saml"
	"github.com/go-chi/chi/v5"
)

// Service is the minimum SAML SP surface the handler needs. Implemented
// by root *TheAuth via samlServiceAdapter so this package does not
// import root.
type Service interface {
	BeginLogin(ctx context.Context, connectionID models.ULID, relayState string) (string, error)
	FinishLogin(ctx context.Context, connectionID models.ULID, samlResponseB64, ua, ip string) (string, error)
	MetadataXML(ctx context.Context, connectionID models.ULID) ([]byte, error)
}

// SessionCookieConfig is the session cookie shape used after a
// successful ACS post.
type SessionCookieConfig struct {
	Name       string
	SecureFlag bool
	TTL        time.Duration
}

// Handler owns the three SAML SP HTTP endpoints.
type Handler struct {
	svc               Service
	sessionCookie     SessionCookieConfig
	postLoginRedirect string
}

// New constructs a Handler. postLoginRedirect is the URL the browser
// is sent to when the IdP did not include a RelayState.
func New(svc Service, sessionCookie SessionCookieConfig, postLoginRedirect string) *Handler {
	return &Handler{svc: svc, sessionCookie: sessionCookie, postLoginRedirect: postLoginRedirect}
}

// Mount registers /saml/{connectionId}/* under r.
func (h *Handler) Mount(r chi.Router) {
	r.Route("/saml", func(r chi.Router) {
		r.Get("/{connectionId}/login", h.handleLogin)
		r.Post("/{connectionId}/acs", h.handleACS)
		r.Get("/{connectionId}/metadata", h.handleMetadata)
	})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	id, ok := pathULID(w, r, "connectionId")
	if !ok {
		return
	}
	relay := r.URL.Query().Get("RelayState")
	if relay == "" {
		relay = h.postLoginRedirect
	}
	redirect, err := h.svc.BeginLogin(r.Context(), id, relay)
	if err != nil {
		http.Error(w, "saml login failed", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (h *Handler) handleACS(w http.ResponseWriter, r *http.Request) {
	id, ok := pathULID(w, r, "connectionId")
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	samlResponse := r.FormValue("SAMLResponse")
	if samlResponse == "" {
		http.Error(w, "missing SAMLResponse", http.StatusBadRequest)
		return
	}
	relayState := r.FormValue("RelayState")
	token, err := h.svc.FinishLogin(r.Context(), id, samlResponse, r.UserAgent(), clientIP(r))
	if err != nil {
		switch {
		case errors.Is(err, saml.ErrSAMLUnsignedAssertion), errors.Is(err, saml.ErrSAMLMissingEmail):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, saml.ErrSAMLInvalidAssertion):
			http.Error(w, "invalid saml assertion", http.StatusForbidden)
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.sessionCookie.Name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.sessionCookie.SecureFlag,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(h.sessionCookie.TTL),
	})
	if relayState == "" {
		relayState = h.postLoginRedirect
	}
	http.Redirect(w, r, relayState, http.StatusFound)
}

func (h *Handler) handleMetadata(w http.ResponseWriter, r *http.Request) {
	id, ok := pathULID(w, r, "connectionId")
	if !ok {
		return
	}
	xmlBytes, err := h.svc.MetadataXML(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(xmlBytes)
}

// pathULID parses a chi path parameter into a ULID. On parse failure
// it writes a 400 response and returns ok=false.
func pathULID(w http.ResponseWriter, r *http.Request, name string) (models.ULID, bool) {
	id, err := httpx.ParseULIDParam(chi.URLParam(r, name))
	if err != nil {
		http.Error(w, "invalid "+name, http.StatusBadRequest)
		return models.ULID{}, false
	}
	return id, true
}

// clientIP extracts the remote IP for audit / session annotation. SAML
// uses an XFF-aware variant (since deployments commonly sit behind a
// load balancer for IdP redirects). The unsigned XFF lookup mirrors
// the legacy root clientIP exactly so audit log content is unchanged.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}
