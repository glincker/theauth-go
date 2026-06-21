// Package handlers exposes the organization-scoped agent + delegation
// administration endpoints mounted under
// /admin/v1/organizations/{orgID}/agents and .../delegations.
//
// Extracted from root handlers_admin_agents.go in PR F of the 2026-06
// architecture reorg. Permission gates: agents:admin and
// delegations:admin per RBAC seed; the gates themselves are supplied
// by the root *TheAuth at Mount time (via the requirePermission
// middleware factory) so this package does not import root.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/glincker/theauth-go/admin"
	"github.com/glincker/theauth-go/internal/httpx"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"
)

// AgentService is the subset of the agent service the admin handler
// needs.
type AgentService interface {
	ListAgentsByOwner(ctx context.Context, owner models.AgentOwner) ([]models.Agent, error)
	CreateAgent(ctx context.Context, in models.CreateAgentInput) (models.Agent, models.AgentSecret, error)
	AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error)
	GetAgent(ctx context.Context, id models.ULID) (*models.Agent, error)
	SuspendAgent(ctx context.Context, agentID models.ULID, reason string) error
	ResumeAgent(ctx context.Context, agentID models.ULID) error
	RevokeAgent(ctx context.Context, agentID models.ULID, reason string) error
}

// DelegationService is the subset of the delegation service the
// admin handler needs.
type DelegationService interface {
	ListDelegationsForUser(ctx context.Context, userID models.ULID) ([]models.DelegationGrant, error)
	ListDelegationsForAgent(ctx context.Context, agentID models.ULID) ([]models.DelegationGrant, error)
	GrantDelegation(ctx context.Context, in models.GrantDelegationInput) (models.DelegationGrant, error)
	GrantByID(ctx context.Context, grantID models.ULID) (*models.DelegationGrant, error)
	RevokeDelegation(ctx context.Context, grantID models.ULID, reason string) error
}

// OrganizationLookup verifies that the named user is a member of the
// organization. Used to short-circuit cross-org delegation minting
// (security audit H3, 2026-06-20).
type OrganizationLookup interface {
	OrganizationMemberRole(ctx context.Context, orgID, userID models.ULID) (string, error)
}

// PermissionGate returns a middleware that rejects requests whose
// session lacks the named permission. Supplied by root because the
// permission machinery lives there.
type PermissionGate func(permission string) func(http.Handler) http.Handler

// Handler owns the seven admin agent + delegation endpoints.
type Handler struct {
	agents      AgentService
	delegations DelegationService
	orgs        OrganizationLookup
}

// New constructs a Handler.
func New(agents AgentService, delegations DelegationService, orgs OrganizationLookup) *Handler {
	return &Handler{agents: agents, delegations: delegations, orgs: orgs}
}

// Mount registers the agent + delegation routes onto r. The router r
// is expected to already be scoped under
// /admin/v1/organizations/{orgID} so the chi URL params resolve.
func (h *Handler) Mount(r chi.Router, requirePermission PermissionGate) {
	r.With(requirePermission(models.PermissionAgentsAdmin)).Get("/agents", h.listAgents)
	r.With(requirePermission(models.PermissionAgentsAdmin)).Post("/agents", h.createAgent)
	r.With(requirePermission(models.PermissionAgentsAdmin)).Patch("/agents/{agentID}", h.patchAgent)
	r.With(requirePermission(models.PermissionAgentsAdmin)).Delete("/agents/{agentID}", h.deleteAgent)

	r.With(requirePermission(models.PermissionDelegationsAdmin)).Get("/delegations", h.listDelegations)
	r.With(requirePermission(models.PermissionDelegationsAdmin)).Post("/delegations", h.createDelegation)
	r.With(requirePermission(models.PermissionDelegationsAdmin)).Delete("/delegations/{grantID}", h.revokeDelegation)
}

// ---------- agents ----------

func (h *Handler) listAgents(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	agents, err := h.agents.ListAgentsByOwner(r.Context(), models.AgentOwner{OrganizationID: &orgID})
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	type response struct {
		Agents []models.Agent `json:"agents"`
		Next   string         `json:"next,omitempty"`
	}
	httpx.WriteJSON(w, http.StatusOK, response{Agents: agents})
}

func (h *Handler) createAgent(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description,omitempty"`
		Scope       []string `json:"scope,omitempty"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "name required", "")
		return
	}
	orgIDCp := orgID
	in := models.CreateAgentInput{
		Owner:       models.AgentOwner{OrganizationID: &orgIDCp},
		Name:        body.Name,
		Description: body.Description,
		Scope:       body.Scope,
	}
	agent, secret, err := h.agents.CreateAgent(r.Context(), in)
	if err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	type response struct {
		Agent       models.Agent       `json:"agent"`
		Credential  models.AgentSecret `json:"credential"`
		ContextHint string             `json:"_note"`
	}
	httpx.WriteJSON(w, http.StatusCreated, response{
		Agent:       agent,
		Credential:  secret,
		ContextHint: "Save the credential.secret value now: it is shown exactly once.",
	})
}

func (h *Handler) patchAgent(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	agentID, ok := httpx.ParseULIDPath(r, "agentID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid agentID", "")
		return
	}
	if err := h.ensureAgentInOrg(r.Context(), agentID, orgID); err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, err.Error(), "")
		return
	}
	var body struct {
		Status string `json:"status,omitempty"`
		Reason string `json:"reason,omitempty"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	var err error
	switch body.Status {
	case models.AgentStatusSuspended:
		err = h.agents.SuspendAgent(r.Context(), agentID, body.Reason)
	case models.AgentStatusActive:
		err = h.agents.ResumeAgent(r.Context(), agentID)
	default:
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "status must be active or suspended", "")
		return
	}
	if err != nil {
		if errors.Is(err, models.ErrAgentInactive) {
			admin.Write(w, http.StatusConflict, admin.CodeValidationInvalid, err.Error(), "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	ag, err := h.agents.GetAgent(r.Context(), agentID)
	if err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, err.Error(), "")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ag)
}

func (h *Handler) deleteAgent(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	agentID, ok := httpx.ParseULIDPath(r, "agentID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid agentID", "")
		return
	}
	if err := h.ensureAgentInOrg(r.Context(), agentID, orgID); err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, err.Error(), "")
		return
	}
	reason := r.URL.Query().Get("reason")
	if err := h.agents.RevokeAgent(r.Context(), agentID, reason); err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- delegations ----------

func (h *Handler) listDelegations(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	userIDStr := r.URL.Query().Get("user_id")
	agentIDStr := r.URL.Query().Get("agent_id")
	if userIDStr == "" && agentIDStr == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "user_id or agent_id query param required", "")
		return
	}
	var grants []models.DelegationGrant
	var err error
	if userIDStr != "" {
		id, perr := ulid.Parse(userIDStr)
		if perr != nil {
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid user_id", "")
			return
		}
		grants, err = h.delegations.ListDelegationsForUser(r.Context(), id)
	} else {
		id, perr := ulid.Parse(agentIDStr)
		if perr != nil {
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid agent_id", "")
			return
		}
		grants, err = h.delegations.ListDelegationsForAgent(r.Context(), id)
	}
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	out := grants[:0]
	for _, g := range grants {
		if g.OrganizationID != nil && *g.OrganizationID == orgID {
			out = append(out, g)
		}
	}
	type response struct {
		Delegations []models.DelegationGrant `json:"delegations"`
		Next        string                   `json:"next,omitempty"`
	}
	httpx.WriteJSON(w, http.StatusOK, response{Delegations: out})
}

func (h *Handler) createDelegation(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	var body struct {
		UserID             string    `json:"userId"`
		AgentID            string    `json:"agentId"`
		Scope              []string  `json:"scope"`
		Resource           string    `json:"resource"`
		MaxDurationSeconds int       `json:"maxDurationSeconds"`
		ExpiresAt          time.Time `json:"expiresAt,omitempty"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	userID, err := ulid.Parse(body.UserID)
	if err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid userId", "")
		return
	}
	agentID, err := ulid.Parse(body.AgentID)
	if err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid agentId", "")
		return
	}
	// security audit H3 (2026-06-20): verify the named user is a member
	// of the calling admin's org before persisting; reject with 403
	// problem+json otherwise. Without this check an admin in any org
	// could mint a delegation_grant naming any user in the system.
	if _, err := h.orgs.OrganizationMemberRole(r.Context(), orgID, userID); err != nil {
		admin.Write(w, http.StatusForbidden, admin.CodeUserNotInOrg, "user is not a member of this organization", "")
		return
	}
	orgIDCp := orgID
	in := models.GrantDelegationInput{
		UserID:             userID,
		AgentID:            agentID,
		OrganizationID:     &orgIDCp,
		Scope:              body.Scope,
		Resource:           body.Resource,
		MaxDurationSeconds: body.MaxDurationSeconds,
	}
	if !body.ExpiresAt.IsZero() {
		t := body.ExpiresAt
		in.ExpiresAt = &t
	}
	grant, err := h.delegations.GrantDelegation(r.Context(), in)
	if err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, grant)
}

func (h *Handler) revokeDelegation(w http.ResponseWriter, r *http.Request) {
	orgID, _ := httpx.ParseULIDPath(r, "orgID")
	grantID, ok := httpx.ParseULIDPath(r, "grantID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid grantID", "")
		return
	}
	grant, err := h.delegations.GrantByID(r.Context(), grantID)
	if err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "delegation grant not found", "")
		return
	}
	if grant.OrganizationID == nil || *grant.OrganizationID != orgID {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "delegation grant not found in this organization", "")
		return
	}
	reason := r.URL.Query().Get("reason")
	if err := h.delegations.RevokeDelegation(r.Context(), grantID, reason); err != nil {
		if errors.Is(err, models.ErrDelegationNotFound) {
			admin.Write(w, http.StatusNotFound, admin.CodeNotFound, err.Error(), "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ensureAgentInOrg returns an error when the supplied agent ID is not
// owned by the supplied organization. Used by the patch + delete
// paths so cross-org tampering returns 404 (no leak of agent
// existence).
func (h *Handler) ensureAgentInOrg(ctx context.Context, agentID, orgID models.ULID) error {
	ag, err := h.agents.AgentByID(ctx, agentID)
	if err != nil {
		return errors.New("agent not found")
	}
	if ag.OrganizationID == nil || *ag.OrganizationID != orgID {
		return errors.New("agent not found in this organization")
	}
	return nil
}
