// Package handlers exposes the /scim/v2/* SCIM 2.0 resource and
// discovery endpoints, plus the per-organization SCIM token CRUD
// endpoints mounted under /auth/orgs/{orgId}/scim/tokens.
//
// Extracted from root handlers_scim.go in PR F of the 2026-06
// architecture reorg. The wire types (UserResource, GroupResource,
// PatchOp, ListResponse, NewError, UserToSCIM, GroupToSCIM, etc.) and
// the PATCH helpers (ApplyUserPatch, ApplyGroupPatch) moved into the
// parent internal/scim package; this package wires them onto chi.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/internal/httpx"
	"github.com/glincker/theauth-go/internal/models"
	internalscim "github.com/glincker/theauth-go/internal/scim"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/go-chi/chi/v5"
	oklogulid "github.com/oklog/ulid/v2"
)

// Storage is the resource-layer persistence surface this handler
// needs. Declared here (not imported from root) so the extracted
// package does not import root.
type Storage interface {
	ListUsersByOrganization(ctx context.Context, orgID models.ULID, offset, limit int, f models.SCIMUserFilter) ([]models.User, int, error)
	CreateUser(ctx context.Context, u models.User) (models.User, error)
	UserByID(ctx context.Context, id models.ULID) (*models.User, error)
	UserByEmail(ctx context.Context, email string) (*models.User, error)
	UserByExternalIDInOrg(ctx context.Context, orgID models.ULID, externalID string) (*models.User, error)
	UpdateUserSCIM(ctx context.Context, u models.User) error
	UpsertOrganizationMember(ctx context.Context, m models.OrganizationMember) error
	DeleteOrganizationMember(ctx context.Context, orgID, userID models.ULID) error
	OrganizationMemberRole(ctx context.Context, orgID, userID models.ULID) (string, error)

	ListGroupsByOrganization(ctx context.Context, orgID models.ULID, offset, limit int, f models.SCIMGroupFilter) ([]models.Group, int, error)
	InsertGroup(ctx context.Context, g models.Group) (models.Group, error)
	UpdateGroup(ctx context.Context, g models.Group) error
	GroupByID(ctx context.Context, id models.ULID) (*models.Group, error)
	GroupByExternalIDInOrg(ctx context.Context, orgID models.ULID, externalID string) (*models.Group, error)
	DeleteGroup(ctx context.Context, id models.ULID) error
	GroupMembers(ctx context.Context, id models.ULID) ([]models.ULID, error)
	SetGroupMembers(ctx context.Context, id models.ULID, userIDs []models.ULID) error
	AddGroupMembers(ctx context.Context, id models.ULID, userIDs []models.ULID) error
	RemoveGroupMembers(ctx context.Context, id models.ULID, userIDs []models.ULID) error
}

// TokenService is the per-org SCIM token CRUD surface the
// /auth/orgs/{orgId}/scim/tokens routes need.
type TokenService interface {
	CreateToken(ctx context.Context, orgID models.ULID, name string) (string, models.SCIMToken, error)
	RevokeToken(ctx context.Context, id models.ULID) error
	ListTokens(ctx context.Context, orgID models.ULID) ([]models.SCIMToken, error)
}

// Config carries the operator-supplied tunables the handler needs at
// request time: BaseURL is used to build SCIM meta.location URLs;
// MaxPageSize caps the list endpoints.
type Config struct {
	BaseURL     string
	MaxPageSize int
}

// AuditEmitter is the audit emit shim. Implemented by root so the
// extracted handler does not import the audit package directly.
type AuditEmitter func(ctx context.Context, action string, orgID, resourceID models.ULID, scimTokenID models.ULID, detail string)

// EnsureMembership re-upserts a member row when the user has been
// soft-deleted. Forwarded from root because the SAML service and SCIM
// handler share this code path.
type EnsureMembership func(ctx context.Context, orgID, userID models.ULID) error

// RoleChecker is the request-scoped role-membership predicate used by
// the SCIM token CRUD endpoints (token mints require OrgRoleOwner).
type RoleChecker func(w http.ResponseWriter, r *http.Request, orgID, userID models.ULID, roles ...string) bool

// UserFromCtx pulls the authenticated user out of the request context
// (used by the token CRUD endpoints; SCIM resource endpoints
// authenticate via scimAuth bearer middleware).
type UserFromCtx func(r *http.Request) (*models.User, bool)

// OrgFromCtx returns the organization ID resolved by the bearer
// middleware for a SCIM request, plus a token-row ID for audit.
type OrgFromCtx func(ctx context.Context) (models.ULID, bool)

// TokenIDFromCtx returns the SCIM token row ID resolved by the bearer
// middleware. Used as the audit actor.
type TokenIDFromCtx func(ctx context.Context) models.ULID

// Handler owns both the /scim/v2/* resource endpoints and the
// per-org token CRUD endpoints.
type Handler struct {
	storage          Storage
	tokenSvc         TokenService
	cfg              Config
	emit             AuditEmitter
	ensureMembership EnsureMembership
	roleCheck        RoleChecker
	userFromCtx      UserFromCtx
	orgFromCtx       OrgFromCtx
	tokenIDFromCtx   TokenIDFromCtx
}

// New constructs the SCIM Handler with every dependency wired.
func New(
	storage Storage,
	tokenSvc TokenService,
	cfg Config,
	emit AuditEmitter,
	ensureMembership EnsureMembership,
	roleCheck RoleChecker,
	userFromCtx UserFromCtx,
	orgFromCtx OrgFromCtx,
	tokenIDFromCtx TokenIDFromCtx,
) *Handler {
	return &Handler{
		storage:          storage,
		tokenSvc:         tokenSvc,
		cfg:              cfg,
		emit:             emit,
		ensureMembership: ensureMembership,
		roleCheck:        roleCheck,
		userFromCtx:      userFromCtx,
		orgFromCtx:       orgFromCtx,
		tokenIDFromCtx:   tokenIDFromCtx,
	}
}

// Mount wires /scim/v2/* under r. The caller supplies the scimAuth
// middleware that resolves the bearer token to an organization (root
// keeps the middleware because it owns the SCIMConfig.RequireHTTPS
// state and the token-lookup paths through Storage; passing it in
// keeps the dep direction one-way).
func (h *Handler) Mount(r chi.Router, scimAuth func(http.Handler) http.Handler) {
	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(scimAuth)
		r.Get("/ServiceProviderConfig", h.handleSPConfig)
		r.Get("/ResourceTypes", h.handleResourceTypes)
		r.Get("/ResourceTypes/User", h.handleResourceTypeUser)
		r.Get("/ResourceTypes/Group", h.handleResourceTypeGroup)
		r.Get("/Schemas", h.handleSchemas)
		r.Get("/Schemas/{id}", h.handleSchemaByID)

		r.Get("/Users", h.handleUsersList)
		r.Post("/Users", h.handleUserCreate)
		r.Get("/Users/{id}", h.handleUserGet)
		r.Patch("/Users/{id}", h.handleUserPatch)
		r.Put("/Users/{id}", h.handleUserPUT)
		r.Delete("/Users/{id}", h.handleUserDelete)

		r.Get("/Groups", h.handleGroupsList)
		r.Post("/Groups", h.handleGroupCreate)
		r.Get("/Groups/{id}", h.handleGroupGet)
		r.Patch("/Groups/{id}", h.handleGroupPatch)
		r.Put("/Groups/{id}", h.handleGroupPUT)
		r.Delete("/Groups/{id}", h.handleGroupDelete)
	})
}

// MountTokenCRUD registers the three /auth/orgs/{orgId}/scim/tokens
// endpoints under r. The caller is expected to scope r under
// /{orgId}/scim/tokens and wrap requests with the session-auth
// middleware.
func (h *Handler) MountTokenCRUD(r chi.Router) {
	r.Post("/", h.handleTokenCreate)
	r.Get("/", h.handleTokenList)
	r.Delete("/{id}", h.handleTokenDelete)
}

// ---------- Discovery ----------

func (h *Handler) handleSPConfig(w http.ResponseWriter, _ *http.Request) {
	maxResults := 200
	if h.cfg.MaxPageSize > 0 {
		maxResults = h.cfg.MaxPageSize
	}
	writeSCIMJSON(w, http.StatusOK, internalscim.ServiceProviderConfig(maxResults))
}

func (h *Handler) handleResourceTypes(w http.ResponseWriter, _ *http.Request) {
	rts := internalscim.ResourceTypes(h.cfg.BaseURL)
	body := map[string]interface{}{
		"schemas":      []string{internalscim.ListSchema},
		"totalResults": len(rts),
		"Resources":    rts,
	}
	writeSCIMJSON(w, http.StatusOK, body)
}

func (h *Handler) handleResourceTypeUser(w http.ResponseWriter, _ *http.Request) {
	writeSCIMJSON(w, http.StatusOK, internalscim.ResourceTypeUser(h.cfg.BaseURL))
}

func (h *Handler) handleResourceTypeGroup(w http.ResponseWriter, _ *http.Request) {
	writeSCIMJSON(w, http.StatusOK, internalscim.ResourceTypeGroup(h.cfg.BaseURL))
}

func (h *Handler) handleSchemas(w http.ResponseWriter, _ *http.Request) {
	schemas := internalscim.Schemas(h.cfg.BaseURL)
	body := map[string]interface{}{
		"schemas":      []string{internalscim.ListSchema},
		"totalResults": len(schemas),
		"Resources":    schemas,
	}
	writeSCIMJSON(w, http.StatusOK, body)
}

func (h *Handler) handleSchemaByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	switch id {
	case internalscim.UserSchema:
		writeSCIMJSON(w, http.StatusOK, internalscim.SchemaUser(h.cfg.BaseURL))
	case internalscim.GroupSchema:
		writeSCIMJSON(w, http.StatusOK, internalscim.SchemaGroup(h.cfg.BaseURL))
	default:
		writeSCIMError(w, http.StatusNotFound, "", "unknown schema id")
	}
}

// ---------- Users ----------

func (h *Handler) handleUsersList(w http.ResponseWriter, r *http.Request) {
	orgID, ok := h.orgFromCtx(r.Context())
	if !ok {
		writeSCIMError(w, http.StatusUnauthorized, "", "no org")
		return
	}
	start, count := pagination(r, h.cfg.MaxPageSize)
	filter, err := internalscim.ParseUserFilter(r.URL.Query().Get("filter"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidFilter", "only eq filters on userName, externalId, emails.value are supported")
		return
	}
	users, total, err := h.storage.ListUsersByOrganization(r.Context(), orgID, start-1, count, filter)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	res := make([]json.RawMessage, 0, len(users))
	for _, u := range users {
		b, _ := json.Marshal(internalscim.UserToSCIM(u, h.cfg.BaseURL))
		res = append(res, b)
	}
	writeSCIMJSON(w, http.StatusOK, internalscim.ListResponse{
		Schemas:      []string{internalscim.ListSchema},
		TotalResults: total,
		StartIndex:   start,
		ItemsPerPage: len(res),
		Resources:    res,
	})
}

type userCreateBody struct {
	Schemas     []string                `json:"schemas"`
	UserName    string                  `json:"userName"`
	ExternalID  string                  `json:"externalId"`
	Name        internalscim.UserName   `json:"name"`
	DisplayName string                  `json:"displayName"`
	Emails      []internalscim.UserEmail `json:"emails"`
	Active      *bool                   `json:"active"`
	Password    string                  `json:"password"`
}

type groupCreateBody struct {
	Schemas     []string                 `json:"schemas"`
	DisplayName string                   `json:"displayName"`
	ExternalID  string                   `json:"externalId"`
	Members     []internalscim.GroupRef  `json:"members"`
}

func (h *Handler) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	orgID, _ := h.orgFromCtx(r.Context())
	var body userCreateBody
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
	if e := internalscim.ParsePrimaryEmail(body.Emails); e != "" {
		email = e
	}

	if body.ExternalID != "" {
		existing, err := h.storage.UserByExternalIDInOrg(r.Context(), orgID, body.ExternalID)
		if errors.Is(err, models.ErrStorageNotFound) {
			if byEmail, eerr := h.storage.UserByEmail(r.Context(), email); eerr == nil && byEmail.ExternalID == body.ExternalID {
				existing = byEmail
				err = nil
			}
		}
		if err == nil && existing != nil {
			existing.Email = email
			existing.GivenName = body.Name.GivenName
			existing.FamilyName = body.Name.FamilyName
			existing.DisplayName = internalscim.NonEmpty(body.DisplayName, body.Name.Formatted)
			existing.Name = internalscim.NonEmpty(body.Name.Formatted, existing.DisplayName)
			if err := h.storage.UpdateUserSCIM(r.Context(), *existing); err != nil {
				writeSCIMError(w, http.StatusInternalServerError, "", "update failed")
				return
			}
			_ = h.ensureMembership(r.Context(), orgID, existing.ID)
			h.emitAudit(r.Context(), "scim.user.create", orgID, existing.ID, "idempotent")
			writeSCIMJSON(w, http.StatusOK, internalscim.UserToSCIM(*existing, h.cfg.BaseURL))
			return
		}
	}

	now := time.Now()
	verified := now
	u := models.User{
		ID:              ulid.New(),
		Email:           email,
		EmailVerifiedAt: &verified,
		Name:            internalscim.NonEmpty(body.Name.Formatted, body.DisplayName),
		GivenName:       body.Name.GivenName,
		FamilyName:      body.Name.FamilyName,
		DisplayName:     internalscim.NonEmpty(body.DisplayName, body.Name.Formatted),
		ExternalID:      body.ExternalID,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	created, err := h.storage.CreateUser(r.Context(), u)
	if err != nil {
		writeSCIMError(w, http.StatusConflict, "uniqueness", "email already exists")
		return
	}
	if err := h.storage.UpsertOrganizationMember(r.Context(), models.OrganizationMember{
		OrganizationID: orgID,
		UserID:         created.ID,
		Role:           models.OrgRoleMember,
	}); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "member upsert failed")
		return
	}
	h.emitAudit(r.Context(), "scim.user.create", orgID, created.ID, "created")
	writeSCIMJSON(w, http.StatusCreated, internalscim.UserToSCIM(created, h.cfg.BaseURL))
}

func (h *Handler) handleUserGet(w http.ResponseWriter, r *http.Request) {
	orgID, _ := h.orgFromCtx(r.Context())
	id, ok := scimPathID(w, r, "id")
	if !ok {
		return
	}
	user, ok := h.lookupUserInOrg(w, r, orgID, id)
	if !ok {
		return
	}
	writeSCIMJSON(w, http.StatusOK, internalscim.UserToSCIM(*user, h.cfg.BaseURL))
}

func (h *Handler) handleUserPatch(w http.ResponseWriter, r *http.Request) {
	orgID, _ := h.orgFromCtx(r.Context())
	id, ok := scimPathID(w, r, "id")
	if !ok {
		return
	}
	user, ok := h.lookupUserInOrg(w, r, orgID, id)
	if !ok {
		return
	}
	var body internalscim.PatchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<17)).Decode(&body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "invalid body")
		return
	}
	active := true
	if err := internalscim.ApplyUserPatch(user, body.Operations, &active); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "unsupported patch op or path")
		return
	}
	if err := h.storage.UpdateUserSCIM(r.Context(), *user); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "update failed")
		return
	}
	if !active {
		_ = h.storage.DeleteOrganizationMember(r.Context(), orgID, user.ID)
	}
	h.emitAudit(r.Context(), "scim.user.patch", orgID, user.ID, "")
	writeSCIMJSON(w, http.StatusOK, internalscim.UserToSCIM(*user, h.cfg.BaseURL))
}

func (h *Handler) handleUserPUT(w http.ResponseWriter, _ *http.Request) {
	writeSCIMError(w, http.StatusMethodNotAllowed, "", "PUT is not supported; use PATCH")
}

func (h *Handler) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	orgID, _ := h.orgFromCtx(r.Context())
	id, ok := scimPathID(w, r, "id")
	if !ok {
		return
	}
	user, ok := h.lookupUserInOrg(w, r, orgID, id)
	if !ok {
		return
	}
	if err := h.storage.DeleteOrganizationMember(r.Context(), orgID, user.ID); err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "not found")
		return
	}
	h.emitAudit(r.Context(), "scim.user.delete", orgID, user.ID, "")
	w.WriteHeader(http.StatusNoContent)
}

// ---------- Groups ----------

func (h *Handler) handleGroupsList(w http.ResponseWriter, r *http.Request) {
	orgID, _ := h.orgFromCtx(r.Context())
	start, count := pagination(r, h.cfg.MaxPageSize)
	filter, err := internalscim.ParseGroupFilter(r.URL.Query().Get("filter"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidFilter", "only eq filters on displayName, externalId are supported")
		return
	}
	groups, total, err := h.storage.ListGroupsByOrganization(r.Context(), orgID, start-1, count, filter)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	res := make([]json.RawMessage, 0, len(groups))
	for _, g := range groups {
		members, _ := h.storage.GroupMembers(r.Context(), g.ID)
		b, _ := json.Marshal(internalscim.GroupToSCIM(g, members, h.cfg.BaseURL))
		res = append(res, b)
	}
	writeSCIMJSON(w, http.StatusOK, internalscim.ListResponse{
		Schemas:      []string{internalscim.ListSchema},
		TotalResults: total,
		StartIndex:   start,
		ItemsPerPage: len(res),
		Resources:    res,
	})
}

func (h *Handler) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	orgID, _ := h.orgFromCtx(r.Context())
	var body groupCreateBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "invalid body")
		return
	}
	if body.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "displayName is required")
		return
	}
	for _, m := range body.Members {
		if strings.EqualFold(m.Type, "Group") {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "nested groups are not supported")
			return
		}
	}
	if body.ExternalID != "" {
		if existing, err := h.storage.GroupByExternalIDInOrg(r.Context(), orgID, body.ExternalID); err == nil {
			existing.DisplayName = body.DisplayName
			if err := h.storage.UpdateGroup(r.Context(), *existing); err != nil {
				writeSCIMError(w, http.StatusInternalServerError, "", "update failed")
				return
			}
			ids, perr := refsToULIDs(body.Members)
			if perr != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid member ref")
				return
			}
			_ = h.storage.SetGroupMembers(r.Context(), existing.ID, ids)
			members, _ := h.storage.GroupMembers(r.Context(), existing.ID)
			h.emitAudit(r.Context(), "scim.group.create", orgID, existing.ID, "idempotent")
			writeSCIMJSON(w, http.StatusOK, internalscim.GroupToSCIM(*existing, members, h.cfg.BaseURL))
			return
		}
	}
	now := time.Now()
	g := models.Group{
		ID:             ulid.New(),
		OrganizationID: orgID,
		DisplayName:    body.DisplayName,
		ExternalID:     body.ExternalID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	created, err := h.storage.InsertGroup(r.Context(), g)
	if err != nil {
		writeSCIMError(w, http.StatusConflict, "uniqueness", "displayName already exists")
		return
	}
	ids, perr := refsToULIDs(body.Members)
	if perr != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid member ref")
		return
	}
	if err := h.storage.SetGroupMembers(r.Context(), created.ID, ids); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "member assignment failed")
		return
	}
	members, _ := h.storage.GroupMembers(r.Context(), created.ID)
	h.emitAudit(r.Context(), "scim.group.create", orgID, created.ID, "")
	writeSCIMJSON(w, http.StatusCreated, internalscim.GroupToSCIM(created, members, h.cfg.BaseURL))
}

func (h *Handler) handleGroupGet(w http.ResponseWriter, r *http.Request) {
	orgID, _ := h.orgFromCtx(r.Context())
	id, ok := scimPathID(w, r, "id")
	if !ok {
		return
	}
	g, err := h.storage.GroupByID(r.Context(), id)
	if err != nil || g.OrganizationID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "not found")
		return
	}
	members, _ := h.storage.GroupMembers(r.Context(), g.ID)
	writeSCIMJSON(w, http.StatusOK, internalscim.GroupToSCIM(*g, members, h.cfg.BaseURL))
}

func (h *Handler) handleGroupPatch(w http.ResponseWriter, r *http.Request) {
	orgID, _ := h.orgFromCtx(r.Context())
	id, ok := scimPathID(w, r, "id")
	if !ok {
		return
	}
	g, err := h.storage.GroupByID(r.Context(), id)
	if err != nil || g.OrganizationID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "not found")
		return
	}
	var body internalscim.PatchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<17)).Decode(&body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "invalid body")
		return
	}
	adds, removes, err := internalscim.ApplyGroupPatch(g, body.Operations)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "unsupported patch")
		return
	}
	if err := h.storage.UpdateGroup(r.Context(), *g); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "update failed")
		return
	}
	hasReplace := false
	cleanRemoves := make([]models.ULID, 0, len(removes))
	for _, u := range removes {
		if u == internalscim.SentinelClearAll {
			hasReplace = true
			continue
		}
		cleanRemoves = append(cleanRemoves, u)
	}
	if hasReplace {
		_ = h.storage.SetGroupMembers(r.Context(), g.ID, adds)
	} else {
		if len(adds) > 0 {
			_ = h.storage.AddGroupMembers(r.Context(), g.ID, adds)
		}
		if len(cleanRemoves) > 0 {
			_ = h.storage.RemoveGroupMembers(r.Context(), g.ID, cleanRemoves)
		}
	}
	members, _ := h.storage.GroupMembers(r.Context(), g.ID)
	h.emitAudit(r.Context(), "scim.group.patch", orgID, g.ID, "")
	writeSCIMJSON(w, http.StatusOK, internalscim.GroupToSCIM(*g, members, h.cfg.BaseURL))
}

func (h *Handler) handleGroupPUT(w http.ResponseWriter, _ *http.Request) {
	writeSCIMError(w, http.StatusMethodNotAllowed, "", "PUT is not supported; use PATCH")
}

func (h *Handler) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	orgID, _ := h.orgFromCtx(r.Context())
	id, ok := scimPathID(w, r, "id")
	if !ok {
		return
	}
	g, err := h.storage.GroupByID(r.Context(), id)
	if err != nil || g.OrganizationID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "not found")
		return
	}
	if err := h.storage.DeleteGroup(r.Context(), id); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "delete failed")
		return
	}
	h.emitAudit(r.Context(), "scim.group.delete", orgID, id, "")
	w.WriteHeader(http.StatusNoContent)
}

// ---------- SCIM token CRUD ----------

func (h *Handler) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	orgID, ok := httpx.PathULID(w, r, "orgId")
	if !ok || user == nil {
		return
	}
	if !h.roleCheck(w, r, orgID, user.ID, models.OrgRoleOwner) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	token, rec, err := h.tokenSvc.CreateToken(r.Context(), orgID, body.Name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, struct {
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

func (h *Handler) handleTokenList(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	orgID, ok := httpx.PathULID(w, r, "orgId")
	if !ok || user == nil {
		return
	}
	if !h.roleCheck(w, r, orgID, user.ID, models.OrgRoleAdmin, models.OrgRoleOwner) {
		return
	}
	tokens, err := h.tokenSvc.ListTokens(r.Context(), orgID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, tokens)
}

func (h *Handler) handleTokenDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := h.userFromCtx(r)
	orgID, ok := httpx.PathULID(w, r, "orgId")
	id, ok2 := httpx.PathULID(w, r, "id")
	if !ok || !ok2 || user == nil {
		return
	}
	if !h.roleCheck(w, r, orgID, user.ID, models.OrgRoleOwner) {
		return
	}
	if err := h.tokenSvc.RevokeToken(r.Context(), id); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- helpers ----------

func (h *Handler) lookupUserInOrg(w http.ResponseWriter, r *http.Request, orgID, userID models.ULID) (*models.User, bool) {
	user, err := h.storage.UserByID(r.Context(), userID)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "not found")
		return nil, false
	}
	if _, err := h.storage.OrganizationMemberRole(r.Context(), orgID, userID); err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "not found")
		return nil, false
	}
	return user, true
}

func (h *Handler) emitAudit(ctx context.Context, action string, orgID, resourceID models.ULID, detail string) {
	if h.emit == nil {
		return
	}
	tokenID := h.tokenIDFromCtx(ctx)
	h.emit(ctx, action, orgID, resourceID, tokenID, detail)
}

func scimPathID(w http.ResponseWriter, r *http.Request, name string) (models.ULID, bool) {
	raw := chi.URLParam(r, name)
	id, err := oklogulid.Parse(raw)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid id")
		return models.ULID{}, false
	}
	return id, true
}

func pagination(r *http.Request, maxPageSize int) (start, count int) {
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

func refsToULIDs(refs []internalscim.GroupRef) ([]models.ULID, error) {
	out := make([]models.ULID, 0, len(refs))
	for _, r := range refs {
		if strings.EqualFold(r.Type, "Group") {
			return nil, errors.New("nested groups not supported")
		}
		if r.Value == "" {
			continue
		}
		id, err := oklogulid.Parse(r.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func writeSCIMJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", internalscim.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", internalscim.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(internalscim.NewError(status, scimType, detail))
}
