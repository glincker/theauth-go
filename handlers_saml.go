package theauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// mountSAML registers the public-facing SAML SP flow endpoints (login,
// ACS, metadata). The connection CRUD endpoints live under
// /auth/orgs/{orgId}/saml/connections and are mounted by
// mountOrganizations.
func (a *TheAuth) mountSAML(r chi.Router) {
	r.Route("/saml", func(r chi.Router) {
		r.Get("/{connectionId}/login", a.handleSAMLLogin)
		r.Post("/{connectionId}/acs", a.handleSAMLACS)
		r.Get("/{connectionId}/metadata", a.handleSAMLMetadata)
	})
}

func (a *TheAuth) handleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	id, ok := pathULID(w, r, "connectionId")
	if !ok {
		return
	}
	relay := r.URL.Query().Get("RelayState")
	if relay == "" {
		relay = a.postLoginRedirect
	}
	redirect, err := a.BeginSAMLLogin(r.Context(), id, relay)
	if err != nil {
		http.Error(w, "saml login failed", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (a *TheAuth) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
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
	token, _, err := a.FinishSAMLLogin(r.Context(), id, samlResponse, r.UserAgent(), clientIP(r))
	if err != nil {
		switch {
		case errors.Is(err, ErrSAMLUnsignedAssertion), errors.Is(err, ErrSAMLMissingEmail):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrSAMLInvalidAssertion):
			http.Error(w, "invalid saml assertion", http.StatusForbidden)
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(a.sessionTTL),
	})
	if relayState == "" {
		relayState = a.postLoginRedirect
	}
	http.Redirect(w, r, relayState, http.StatusFound)
}

func (a *TheAuth) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	id, ok := pathULID(w, r, "connectionId")
	if !ok {
		return
	}
	xmlBytes, err := a.SAMLMetadataXML(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(xmlBytes)
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
