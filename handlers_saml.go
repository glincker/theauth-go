package theauth

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/glincker/theauth-go/internal/models"
	samlhandlers "github.com/glincker/theauth-go/internal/saml/handlers"
	"github.com/go-chi/chi/v5"
)

// samlServiceAdapter implements internal/saml/handlers.Service on top
// of the root *TheAuth, exposing the three SP-flow methods the
// extracted handler needs (BeginLogin, FinishLogin, MetadataXML).
// FinishLogin discards the second return (Session) because the
// handler only writes the cookie.
type samlServiceAdapter struct{ a *TheAuth }

func (s samlServiceAdapter) BeginLogin(ctx context.Context, id models.ULID, relayState string) (string, error) {
	return s.a.BeginSAMLLogin(ctx, id, relayState)
}

func (s samlServiceAdapter) FinishLogin(ctx context.Context, id models.ULID, samlResp, ua, ip string) (string, error) {
	tok, _, err := s.a.FinishSAMLLogin(ctx, id, samlResp, ua, ip)
	return tok, err
}

func (s samlServiceAdapter) MetadataXML(ctx context.Context, id models.ULID) ([]byte, error) {
	return s.a.SAMLMetadataXML(ctx, id)
}

// mountSAML wires the public-facing SAML SP-flow endpoints (login,
// ACS, metadata) via the extracted internal/saml/handlers package.
// PR E architecture reorg (2026-06-20) moved the three SP endpoints
// there; the per-org SAML connection CRUD endpoints below stay in
// root because they depend on the unextracted requireOrgRole helper.
func (a *TheAuth) mountSAML(r chi.Router) {
	h := samlhandlers.New(
		samlServiceAdapter{a: a},
		samlhandlers.SessionCookieConfig{
			Name:       a.cookieName,
			SecureFlag: a.secureCookie,
			TTL:        a.sessionTTL,
		},
		a.postLoginRedirect,
	)
	h.Mount(r)
}

// ---------- SAML connection CRUD (mounted under /auth/orgs/{orgId}/saml/connections) ----------

func (a *TheAuth) handleSAMLConnectionCreate(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	orgID, ok := pathULID(w, r, "orgId")
	if !ok || user == nil {
		return
	}
	if !a.requireOrgRole(w, r, orgID, user.ID, OrgRoleOwner) {
		return
	}
	var body samlConnectionBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	in := body.toInput(orgID)
	conn, err := a.CreateSAMLConnection(r.Context(), in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, conn)
}

func (a *TheAuth) handleSAMLConnectionList(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	orgID, ok := pathULID(w, r, "orgId")
	if !ok || user == nil {
		return
	}
	if !a.requireOrgRole(w, r, orgID, user.ID, OrgRoleAdmin, OrgRoleOwner) {
		return
	}
	conns, err := a.ListSAMLConnections(r.Context(), orgID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, conns)
}

func (a *TheAuth) handleSAMLConnectionGet(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	orgID, ok := pathULID(w, r, "orgId")
	id, ok2 := pathULID(w, r, "id")
	if !ok || !ok2 || user == nil {
		return
	}
	if !a.requireOrgRole(w, r, orgID, user.ID, OrgRoleAdmin, OrgRoleOwner) {
		return
	}
	conn, err := a.SAMLConnectionByID(r.Context(), id)
	if err != nil || conn.OrganizationID != orgID {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, conn)
}

func (a *TheAuth) handleSAMLConnectionUpdate(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	orgID, ok := pathULID(w, r, "orgId")
	id, ok2 := pathULID(w, r, "id")
	if !ok || !ok2 || user == nil {
		return
	}
	if !a.requireOrgRole(w, r, orgID, user.ID, OrgRoleOwner) {
		return
	}
	var body samlConnectionBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	in := body.toInput(orgID)
	conn, err := a.UpdateSAMLConnection(r.Context(), id, in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, conn)
}

func (a *TheAuth) handleSAMLConnectionDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	orgID, ok := pathULID(w, r, "orgId")
	id, ok2 := pathULID(w, r, "id")
	if !ok || !ok2 || user == nil {
		return
	}
	if !a.requireOrgRole(w, r, orgID, user.ID, OrgRoleOwner) {
		return
	}
	if err := a.DeleteSAMLConnection(r.Context(), id); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// samlConnectionBody is the JSON shape consumers POST/PUT.
type samlConnectionBody struct {
	IdPEntityID  string           `json:"idpEntityId"`
	IdPSSOURL    string           `json:"idpSsoUrl"`
	IdPX509Cert  string           `json:"idpX509Cert"`
	SPEntityID   string           `json:"spEntityId"`
	SPACSURL     string           `json:"spAcsUrl"`
	AttributeMap SAMLAttributeMap `json:"attributeMap"`
}

func (b samlConnectionBody) toInput(orgID ULID) SAMLConnectionInput {
	return SAMLConnectionInput{
		OrganizationID: orgID,
		IdPEntityID:    b.IdPEntityID,
		IdPSSOURL:      b.IdPSSOURL,
		IdPX509Cert:    b.IdPX509Cert,
		SPEntityID:     b.SPEntityID,
		SPACSURL:       b.SPACSURL,
		AttributeMap:   b.AttributeMap,
	}
}

// clientIP extracts the remote IP for audit / session annotation. Falls
// back to RemoteAddr when X-Forwarded-For is absent.
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
