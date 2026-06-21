package theauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/go-chi/chi/v5"
)

// mountSCIM registers the /scim/v2/* SCIM 2.0 resource and discovery
// endpoints. Each handler is wrapped with scimAuth so bearer + HTTPS are
// enforced at the door.
func (a *TheAuth) mountSCIM(r chi.Router) {
	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(a.scimAuth())

		// Discovery (RFC 7644 §5 + §6).
		r.Get("/ServiceProviderConfig", a.handleSCIMSPConfig)
		r.Get("/ResourceTypes", a.handleSCIMResourceTypes)
		r.Get("/ResourceTypes/User", a.handleSCIMResourceTypeUser)
		r.Get("/ResourceTypes/Group", a.handleSCIMResourceTypeGroup)
		r.Get("/Schemas", a.handleSCIMSchemas)
		r.Get("/Schemas/{id}", a.handleSCIMSchemaByID)

		// Users.
		r.Get("/Users", a.handleSCIMUsersList)
		r.Post("/Users", a.handleSCIMUserCreate)
		r.Get("/Users/{id}", a.handleSCIMUserGet)
		r.Patch("/Users/{id}", a.handleSCIMUserPatch)
		r.Put("/Users/{id}", a.handleSCIMUserPUT)
		r.Delete("/Users/{id}", a.handleSCIMUserDelete)

		// Groups.
		r.Get("/Groups", a.handleSCIMGroupsList)
		r.Post("/Groups", a.handleSCIMGroupCreate)
		r.Get("/Groups/{id}", a.handleSCIMGroupGet)
		r.Patch("/Groups/{id}", a.handleSCIMGroupPatch)
		r.Put("/Groups/{id}", a.handleSCIMGroupPUT)
		r.Delete("/Groups/{id}", a.handleSCIMGroupDelete)
	})
}

// ---------- Discovery ----------

func (a *TheAuth) handleSCIMSPConfig(w http.ResponseWriter, _ *http.Request) {
	maxResults := 200
	if a.scimCfg != nil && a.scimCfg.MaxPageSize > 0 {
		maxResults = a.scimCfg.MaxPageSize
	}
	writeSCIMJSON(w, http.StatusOK, scimServiceProviderConfig(maxResults))
}

func (a *TheAuth) handleSCIMResourceTypes(w http.ResponseWriter, _ *http.Request) {
	rts := scimResourceTypes(a.baseURL)
	body := map[string]interface{}{
		"schemas":      []string{scimListSchema},
		"totalResults": len(rts),
		"Resources":    rts,
	}
	writeSCIMJSON(w, http.StatusOK, body)
}

func (a *TheAuth) handleSCIMResourceTypeUser(w http.ResponseWriter, _ *http.Request) {
	writeSCIMJSON(w, http.StatusOK, scimResourceTypeUser(a.baseURL))
}

func (a *TheAuth) handleSCIMResourceTypeGroup(w http.ResponseWriter, _ *http.Request) {
	writeSCIMJSON(w, http.StatusOK, scimResourceTypeGroup(a.baseURL))
}

func (a *TheAuth) handleSCIMSchemas(w http.ResponseWriter, _ *http.Request) {
	schemas := scimSchemas(a.baseURL)
	body := map[string]interface{}{
		"schemas":      []string{scimListSchema},
		"totalResults": len(schemas),
		"Resources":    schemas,
	}
	writeSCIMJSON(w, http.StatusOK, body)
}

func (a *TheAuth) handleSCIMSchemaByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	switch id {
	case scimUserSchema:
		writeSCIMJSON(w, http.StatusOK, scimSchemaUser(a.baseURL))
	case scimGroupSchema:
		writeSCIMJSON(w, http.StatusOK, scimSchemaGroup(a.baseURL))
	default:
		writeSCIMError(w, http.StatusNotFound, "", "unknown schema id")
	}
}

// ---------- Users ----------

func (a *TheAuth) handleSCIMUsersList(w http.ResponseWriter, r *http.Request) {
	orgID, ok := scimOrgFromContext(r.Context())
	if !ok {
		writeSCIMError(w, http.StatusUnauthorized, "", "no org")
		return
	}
	start, count := scimPagination(r, a.scimCfg.MaxPageSize)
	filter, err := parseSCIMUserFilter(r.URL.Query().Get("filter"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidFilter", "only eq filters on userName, externalId, emails.value are supported")
		return
	}
	users, total, err := a.storage.ListUsersByOrganization(r.Context(), orgID, start-1, count, filter)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	res := make([]json.RawMessage, 0, len(users))
	for _, u := range users {
		b, _ := json.Marshal(userToSCIM(u, a.baseURL))
		res = append(res, b)
	}
	writeSCIMJSON(w, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListSchema},
		TotalResults: total,
		StartIndex:   start,
		ItemsPerPage: len(res),
		Resources:    res,
	})
}

func (a *TheAuth) handleSCIMUserCreate(w http.ResponseWriter, r *http.Request) {
	orgID, _ := scimOrgFromContext(r.Context())
	var body scimUserCreateBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<17)).Decode(&body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "invalid body")
		return
	}
	if body.Password != "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "password is not provisionable via SCIM")
		return
	}
	if body.UserName == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}
	email := strings.ToLower(body.UserName)
	if e := parsePrimaryEmail(body.Emails); e != "" {
		email = e
	}

	// Idempotent upsert by externalId scoped to org.
	if body.ExternalID != "" {
		if existing, err := a.storage.UserByExternalIDInOrg(r.Context(), orgID, body.ExternalID); err == nil {
			// Update names in place to honour idempotent re-POST.
			existing.Email = email
			existing.GivenName = body.Name.GivenName
			existing.FamilyName = body.Name.FamilyName
			existing.DisplayName = nonEmpty(body.DisplayName, body.Name.Formatted)
			existing.Name = nonEmpty(body.Name.Formatted, existing.DisplayName)
			if err := a.storage.UpdateUserSCIM(r.Context(), *existing); err != nil {
				writeSCIMError(w, http.StatusInternalServerError, "", "update failed")
				return
			}
			// Make sure they're still a member of the org (re-POST after
			// a soft-delete should re-enable).
			_ = a.ensureOrgMembership(r.Context(), orgID, existing.ID)
			a.emitSCIMAudit(r.Context(), "scim.user.create", orgID, existing.ID, "idempotent")
			writeSCIMJSON(w, http.StatusOK, userToSCIM(*existing, a.baseURL))
			return
		}
	}

	now := time.Now()
	verified := now
	u := User{
		ID:              ulid.New(),
		Email:           email,
		EmailVerifiedAt: &verified,
		Name:            nonEmpty(body.Name.Formatted, body.DisplayName),
		GivenName:       body.Name.GivenName,
		FamilyName:      body.Name.FamilyName,
		DisplayName:     nonEmpty(body.DisplayName, body.Name.Formatted),
		ExternalID:      body.ExternalID,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	created, err := a.storage.CreateUser(r.Context(), u)
	if err != nil {
		writeSCIMError(w, http.StatusConflict, "uniqueness", "email already exists")
		return
	}
	if err := a.storage.UpsertOrganizationMember(r.Context(), OrganizationMember{
		OrganizationID: orgID,
		UserID:         created.ID,
		Role:           OrgRoleMember,
	}); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "member upsert failed")
		return
	}
	a.emitSCIMAudit(r.Context(), "scim.user.create", orgID, created.ID, "created")
	writeSCIMJSON(w, http.StatusCreated, userToSCIM(created, a.baseURL))
}

func (a *TheAuth) handleSCIMUserGet(w http.ResponseWriter, r *http.Request) {
	orgID, _ := scimOrgFromContext(r.Context())
	id, ok := scimPathID(w, r, "id")
	if !ok {
		return
	}
	user, ok := a.scimLookupUserInOrg(w, r, orgID, id)
	if !ok {
		return
	}
	writeSCIMJSON(w, http.StatusOK, userToSCIM(*user, a.baseURL))
}

func (a *TheAuth) handleSCIMUserPatch(w http.ResponseWriter, r *http.Request) {
	orgID, _ := scimOrgFromContext(r.Context())
	id, ok := scimPathID(w, r, "id")
	if !ok {
		return
	}
	user, ok := a.scimLookupUserInOrg(w, r, orgID, id)
	if !ok {
		return
	}
	var body scimPatchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<17)).Decode(&body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "invalid body")
		return
	}
	active := true
	if err := applySCIMUserPatch(user, body.Operations, &active); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "unsupported patch op or path")
		return
	}
	if err := a.storage.UpdateUserSCIM(r.Context(), *user); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "update failed")
		return
	}
	if !active {
		_ = a.storage.DeleteOrganizationMember(r.Context(), orgID, user.ID)
	}
	a.emitSCIMAudit(r.Context(), "scim.user.patch", orgID, user.ID, "")
	writeSCIMJSON(w, http.StatusOK, userToSCIM(*user, a.baseURL))
}

func (a *TheAuth) handleSCIMUserPUT(w http.ResponseWriter, _ *http.Request) {
	writeSCIMError(w, http.StatusMethodNotAllowed, "", "PUT is not supported; use PATCH")
}

func (a *TheAuth) handleSCIMUserDelete(w http.ResponseWriter, r *http.Request) {
	orgID, _ := scimOrgFromContext(r.Context())
	id, ok := scimPathID(w, r, "id")
	if !ok {
		return
	}
	user, ok := a.scimLookupUserInOrg(w, r, orgID, id)
	if !ok {
		return
	}
	if err := a.storage.DeleteOrganizationMember(r.Context(), orgID, user.ID); err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "not found")
		return
	}
	a.emitSCIMAudit(r.Context(), "scim.user.delete", orgID, user.ID, "")
	w.WriteHeader(http.StatusNoContent)
}

// ---------- Groups ----------

func (a *TheAuth) handleSCIMGroupsList(w http.ResponseWriter, r *http.Request) {
	orgID, _ := scimOrgFromContext(r.Context())
	start, count := scimPagination(r, a.scimCfg.MaxPageSize)
	filter, err := parseSCIMGroupFilter(r.URL.Query().Get("filter"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidFilter", "only eq filters on displayName, externalId are supported")
		return
	}
	groups, total, err := a.storage.ListGroupsByOrganization(r.Context(), orgID, start-1, count, filter)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	res := make([]json.RawMessage, 0, len(groups))
	for _, g := range groups {
		members, _ := a.storage.GroupMembers(r.Context(), g.ID)
		b, _ := json.Marshal(groupToSCIM(g, members, a.baseURL))
		res = append(res, b)
	}
	writeSCIMJSON(w, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListSchema},
		TotalResults: total,
		StartIndex:   start,
		ItemsPerPage: len(res),
		Resources:    res,
	})
}

func (a *TheAuth) handleSCIMGroupCreate(w http.ResponseWriter, r *http.Request) {
	orgID, _ := scimOrgFromContext(r.Context())
	var body scimGroupCreateBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "invalid body")
		return
	}
	if body.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "displayName is required")
		return
	}
	// Reject nested groups (members[i].type=="Group").
	for _, m := range body.Members {
		if strings.EqualFold(m.Type, "Group") {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "nested groups are not supported")
			return
		}
	}
	// Idempotent upsert by externalId scoped to org.
	if body.ExternalID != "" {
		if existing, err := a.storage.GroupByExternalIDInOrg(r.Context(), orgID, body.ExternalID); err == nil {
			existing.DisplayName = body.DisplayName
			if err := a.storage.UpdateGroup(r.Context(), *existing); err != nil {
				writeSCIMError(w, http.StatusInternalServerError, "", "update failed")
				return
			}
			ids, perr := scimRefsToULIDs(body.Members)
			if perr != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid member ref")
				return
			}
			_ = a.storage.SetGroupMembers(r.Context(), existing.ID, ids)
			members, _ := a.storage.GroupMembers(r.Context(), existing.ID)
			a.emitSCIMAudit(r.Context(), "scim.group.create", orgID, existing.ID, "idempotent")
			writeSCIMJSON(w, http.StatusOK, groupToSCIM(*existing, members, a.baseURL))
			return
		}
	}
	now := time.Now()
	g := Group{
		ID:             ulid.New(),
		OrganizationID: orgID,
		DisplayName:    body.DisplayName,
		ExternalID:     body.ExternalID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	created, err := a.storage.InsertGroup(r.Context(), g)
	if err != nil {
		writeSCIMError(w, http.StatusConflict, "uniqueness", "displayName already exists")
		return
	}
	ids, perr := scimRefsToULIDs(body.Members)
	if perr != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid member ref")
		return
	}
	if err := a.storage.SetGroupMembers(r.Context(), created.ID, ids); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "member assignment failed")
		return
	}
	members, _ := a.storage.GroupMembers(r.Context(), created.ID)
	a.emitSCIMAudit(r.Context(), "scim.group.create", orgID, created.ID, "")
	writeSCIMJSON(w, http.StatusCreated, groupToSCIM(created, members, a.baseURL))
}

func (a *TheAuth) handleSCIMGroupGet(w http.ResponseWriter, r *http.Request) {
	orgID, _ := scimOrgFromContext(r.Context())
	id, ok := scimPathID(w, r, "id")
	if !ok {
		return
	}
	g, err := a.storage.GroupByID(r.Context(), id)
	if err != nil || g.OrganizationID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "not found")
		return
	}
	members, _ := a.storage.GroupMembers(r.Context(), g.ID)
	writeSCIMJSON(w, http.StatusOK, groupToSCIM(*g, members, a.baseURL))
}

func (a *TheAuth) handleSCIMGroupPatch(w http.ResponseWriter, r *http.Request) {
	orgID, _ := scimOrgFromContext(r.Context())
	id, ok := scimPathID(w, r, "id")
	if !ok {
		return
	}
	g, err := a.storage.GroupByID(r.Context(), id)
	if err != nil || g.OrganizationID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "not found")
		return
	}
	var body scimPatchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<17)).Decode(&body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "invalid body")
		return
	}
	adds, removes, err := applySCIMGroupPatch(g, body.Operations)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "unsupported patch")
		return
	}
	if err := a.storage.UpdateGroup(r.Context(), *g); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "update failed")
		return
	}
	// Replace-via-PATCH sentinel: when the sentinel ULID is present in
	// removes, treat the operation as SetGroupMembers(adds).
	hasReplace := false
	cleanRemoves := make([]ULID, 0, len(removes))
	for _, u := range removes {
		if u == sentinelClearAll {
			hasReplace = true
			continue
		}
		cleanRemoves = append(cleanRemoves, u)
	}
	if hasReplace {
		_ = a.storage.SetGroupMembers(r.Context(), g.ID, adds)
	} else {
		if len(adds) > 0 {
			_ = a.storage.AddGroupMembers(r.Context(), g.ID, adds)
		}
		if len(cleanRemoves) > 0 {
			_ = a.storage.RemoveGroupMembers(r.Context(), g.ID, cleanRemoves)
		}
	}
	members, _ := a.storage.GroupMembers(r.Context(), g.ID)
	a.emitSCIMAudit(r.Context(), "scim.group.patch", orgID, g.ID, "")
	writeSCIMJSON(w, http.StatusOK, groupToSCIM(*g, members, a.baseURL))
}

func (a *TheAuth) handleSCIMGroupPUT(w http.ResponseWriter, _ *http.Request) {
	writeSCIMError(w, http.StatusMethodNotAllowed, "", "PUT is not supported; use PATCH")
}

func (a *TheAuth) handleSCIMGroupDelete(w http.ResponseWriter, r *http.Request) {
	orgID, _ := scimOrgFromContext(r.Context())
	id, ok := scimPathID(w, r, "id")
	if !ok {
		return
	}
	g, err := a.storage.GroupByID(r.Context(), id)
	if err != nil || g.OrganizationID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "not found")
		return
	}
	if err := a.storage.DeleteGroup(r.Context(), id); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "delete failed")
		return
	}
	a.emitSCIMAudit(r.Context(), "scim.group.delete", orgID, id, "")
	w.WriteHeader(http.StatusNoContent)
}

// ---------- SCIM token CRUD (mounted on /auth/orgs/{orgId}/scim/tokens) ----------

func (a *TheAuth) handleSCIMTokenCreate(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	orgID, ok := pathULID(w, r, "orgId")
	if !ok || user == nil {
		return
	}
	if !a.requireOrgRole(w, r, orgID, user.ID, OrgRoleOwner) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	token, rec, err := a.CreateSCIMToken(r.Context(), orgID, body.Name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Token     string    `json:"token"`
		CreatedAt time.Time `json:"createdAt"`
	}{
		ID:        rec.ID.String(),
		Name:      rec.Name,
		Token:     token,
		CreatedAt: rec.CreatedAt,
	})
}

func (a *TheAuth) handleSCIMTokenList(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	orgID, ok := pathULID(w, r, "orgId")
	if !ok || user == nil {
		return
	}
	if !a.requireOrgRole(w, r, orgID, user.ID, OrgRoleAdmin, OrgRoleOwner) {
		return
	}
	tokens, err := a.ListSCIMTokens(r.Context(), orgID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (a *TheAuth) handleSCIMTokenDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	orgID, ok := pathULID(w, r, "orgId")
	id, ok2 := pathULID(w, r, "id")
	if !ok || !ok2 || user == nil {
		return
	}
	if !a.requireOrgRole(w, r, orgID, user.ID, OrgRoleOwner) {
		return
	}
	if err := a.RevokeSCIMToken(r.Context(), id); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- helpers ----------

type scimUserCreateBody struct {
	Schemas     []string        `json:"schemas"`
	UserName    string          `json:"userName"`
	ExternalID  string          `json:"externalId"`
	Name        scimUserName    `json:"name"`
	DisplayName string          `json:"displayName"`
	Emails      []scimUserEmail `json:"emails"`
	Active      *bool           `json:"active"`
	Password    string          `json:"password"`
}

type scimGroupCreateBody struct {
	Schemas     []string       `json:"schemas"`
	DisplayName string         `json:"displayName"`
	ExternalID  string         `json:"externalId"`
	Members     []scimGroupRef `json:"members"`
}

func (a *TheAuth) scimLookupUserInOrg(w http.ResponseWriter, r *http.Request, orgID, userID ULID) (*User, bool) {
	user, err := a.storage.UserByID(r.Context(), userID)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "not found")
		return nil, false
	}
	if _, err := a.storage.OrganizationMemberRole(r.Context(), orgID, userID); err != nil {
		// Per v0.7 §9.8 we return 404 (not 403) to avoid leaking cross-org
		// existence.
		writeSCIMError(w, http.StatusNotFound, "", "not found")
		return nil, false
	}
	return user, true
}

func scimPathID(w http.ResponseWriter, r *http.Request, name string) (ULID, bool) {
	raw := chi.URLParam(r, name)
	id, err := ulidParse(raw)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid id")
		return ULID{}, false
	}
	return id, true
}

func scimPagination(r *http.Request, maxPageSize int) (start, count int) {
	start = 1
	count = 100
	if v := r.URL.Query().Get("startIndex"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			start = n
		}
	}
	if v := r.URL.Query().Get("count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			count = n
		}
	}
	if maxPageSize > 0 && count > maxPageSize {
		count = maxPageSize
	}
	return start, count
}

func scimRefsToULIDs(refs []scimGroupRef) ([]ULID, error) {
	out := make([]ULID, 0, len(refs))
	for _, r := range refs {
		if strings.EqualFold(r.Type, "Group") {
			return nil, errors.New("nested groups not supported")
		}
		if r.Value == "" {
			continue
		}
		id, err := ulidParse(r.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func writeSCIMJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(newSCIMError(status, scimType, detail))
}

// emitSCIMAudit invokes the audit hook with the actor token ID resolved by
// scimAuth. v0.7 ships a no-op default; v1.0 replaces this with the real
// async writer.
func (a *TheAuth) emitSCIMAudit(ctx context.Context, action string, orgID, resourceID ULID, detail string) {
	tokenID := scimTokenIDFromContext(ctx)
	a.auditHook(ctx, AuditEvent{
		Action:         action,
		OrganizationID: orgID,
		ActorID:        tokenID,
		ResourceID:     resourceID,
		Detail:         detail,
		At:             time.Now(),
	})
}
