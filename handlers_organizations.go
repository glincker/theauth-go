package theauth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// mountOrganizations registers the /auth/orgs routes. Only called by
// Mount when Config.Organizations is non-nil.
func (a *TheAuth) mountOrganizations(r chi.Router) {
	r.Route("/orgs", func(r chi.Router) {
		r.With(a.RequireAuth()).Post("/", a.handleOrgCreate)
		r.With(a.RequireAuth()).Get("/", a.handleOrgList)
		r.With(a.RequireAuth()).Get("/{id}", a.handleOrgGet)
		r.With(a.RequireAuth()).Post("/{id}/members", a.handleOrgAddMember)
		r.With(a.RequireAuth()).Delete("/{id}/members/{userId}", a.handleOrgRemoveMember)
		r.With(a.RequireAuth()).Post("/{id}/activate", a.handleOrgActivate)
		r.With(a.RequireAuth()).Post("/clear-active", a.handleOrgClearActive)

		// SAML connection management (mounted only when SAML is on).
		if a.samlCfg != nil {
			r.Route("/{orgId}/saml/connections", func(r chi.Router) {
				r.With(a.RequireAuth()).Post("/", a.handleSAMLConnectionCreate)
				r.With(a.RequireAuth()).Get("/", a.handleSAMLConnectionList)
				r.With(a.RequireAuth()).Get("/{id}", a.handleSAMLConnectionGet)
				r.With(a.RequireAuth()).Put("/{id}", a.handleSAMLConnectionUpdate)
				r.With(a.RequireAuth()).Delete("/{id}", a.handleSAMLConnectionDelete)
			})
		}
		// SCIM token management.
		if a.scimCfg != nil {
			r.Route("/{orgId}/scim/tokens", func(r chi.Router) {
				r.With(a.RequireAuth()).Post("/", a.handleSCIMTokenCreate)
				r.With(a.RequireAuth()).Get("/", a.handleSCIMTokenList)
				r.With(a.RequireAuth()).Delete("/{id}", a.handleSCIMTokenDelete)
			})
		}
	})
}

func (a *TheAuth) handleOrgCreate(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	org, err := a.CreateOrganization(r.Context(), body.Name, body.Slug, user.ID)
	if err != nil {
		if errors.Is(err, ErrSlugTaken) {
			http.Error(w, "slug already taken", http.StatusConflict)
			return
		}
		http.Error(w, "invalid organization", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, org)
}

func (a *TheAuth) handleOrgList(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	orgs, err := a.ListUserOrganizations(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, orgs)
}

func (a *TheAuth) handleOrgGet(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	id, ok := pathULID(w, r, "id")
	if !ok || user == nil {
		return
	}
	if !a.requireOrgRole(w, r, id, user.ID, OrgRoleMember, OrgRoleAdmin, OrgRoleOwner) {
		return
	}
	org, err := a.OrganizationByID(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (a *TheAuth) handleOrgAddMember(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	id, ok := pathULID(w, r, "id")
	if !ok || user == nil {
		return
	}
	if !a.requireOrgRole(w, r, id, user.ID, OrgRoleAdmin, OrgRoleOwner) {
		return
	}
	var body struct {
		UserID string `json:"userId"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	uid, err := ulidParse(body.UserID)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	if err := a.AddOrganizationMember(r.Context(), id, uid, body.Role); err != nil {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *TheAuth) handleOrgRemoveMember(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	id, ok := pathULID(w, r, "id")
	uid, ok2 := pathULID(w, r, "userId")
	if !ok || !ok2 || user == nil {
		return
	}
	if !a.requireOrgRole(w, r, id, user.ID, OrgRoleOwner) {
		return
	}
	if err := a.RemoveOrganizationMember(r.Context(), id, uid); err != nil {
		if errors.Is(err, ErrLastOwner) {
			http.Error(w, "cannot remove the last owner", http.StatusConflict)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *TheAuth) handleOrgActivate(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	user, _ := UserFromContext(r.Context())
	id, ok := pathULID(w, r, "id")
	if !ok || sess == nil || user == nil {
		return
	}
	if !a.requireOrgRole(w, r, id, user.ID, OrgRoleMember, OrgRoleAdmin, OrgRoleOwner) {
		return
	}
	orgID := id
	if err := a.SetActiveOrganization(r.Context(), sess.ID, &orgID); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *TheAuth) handleOrgClearActive(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	if sess == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := a.SetActiveOrganization(r.Context(), sess.ID, nil); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// requireOrgRole returns true when the user holds one of the supplied
// roles in the org. Writes a 403 + returns false otherwise.
func (a *TheAuth) requireOrgRole(w http.ResponseWriter, r *http.Request, orgID, userID ULID, roles ...string) bool {
	role, err := a.storage.OrganizationMemberRole(r.Context(), orgID, userID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return false
	}
	for _, want := range roles {
		if role == want {
			return true
		}
	}
	http.Error(w, "forbidden", http.StatusForbidden)
	return false
}

// pathULID parses a chi path parameter into a ULID. On error writes a 400
// and returns false.
func pathULID(w http.ResponseWriter, r *http.Request, name string) (ULID, bool) {
	raw := chi.URLParam(r, name)
	id, err := ulidParse(raw)
	if err != nil {
		http.Error(w, "invalid "+name, http.StatusBadRequest)
		return ULID{}, false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
