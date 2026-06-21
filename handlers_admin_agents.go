package theauth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/glincker/theauth-go/admin"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"
)

// handlers_admin_agents.go: organization-scoped agent + delegation
// administration. Mounted on the /admin/v1/.../agents and
// /admin/v1/.../delegations subtrees when Config.Admin and
// Config.AgentIdentity are both set. Permission gates: agents:admin and
// delegations:admin per RBAC seed.

// mountAdminAgents adds the agent + delegation routes to the existing
// /admin/v1/organizations/{orgID} subtree. Called from mountAdmin when the
// agent identity service is configured.
func (a *TheAuth) mountAdminAgents(r chi.Router) {
	if a.agentCfg == nil || a.as == nil {
		return
	}
	r.With(a.RequirePermission(PermissionAgentsAdmin)).Get("/agents", a.adminListAgents)
	r.With(a.RequirePermission(PermissionAgentsAdmin)).Post("/agents", a.adminCreateAgent)
	r.With(a.RequirePermission(PermissionAgentsAdmin)).Patch("/agents/{agentID}", a.adminPatchAgent)
	r.With(a.RequirePermission(PermissionAgentsAdmin)).Delete("/agents/{agentID}", a.adminDeleteAgent)

	r.With(a.RequirePermission(PermissionDelegationsAdmin)).Get("/delegations", a.adminListDelegations)
	r.With(a.RequirePermission(PermissionDelegationsAdmin)).Post("/delegations", a.adminCreateDelegation)
	r.With(a.RequirePermission(PermissionDelegationsAdmin)).Delete("/delegations/{grantID}", a.adminRevokeDelegation)
}

// ---------- agents ----------

func (a *TheAuth) adminListAgents(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	owner := AgentOwner{OrganizationID: &orgID}
	agents, err := a.ListAgentsByOwner(r.Context(), owner)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	type response struct {
		Agents []Agent `json:"agents"`
		Next   string  `json:"next,omitempty"`
	}
	writeJSON(w, http.StatusOK, response{Agents: agents})
}

func (a *TheAuth) adminCreateAgent(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description,omitempty"`
		Scope       []string `json:"scope,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "name required", "")
		return
	}
	orgIDCp := orgID
	in := CreateAgentInput{
		Owner:       AgentOwner{OrganizationID: &orgIDCp},
		Name:        body.Name,
		Description: body.Description,
		Scope:       body.Scope,
	}
	agent, secret, err := a.CreateAgent(r.Context(), in)
	if err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	type response struct {
		Agent       Agent       `json:"agent"`
		Credential  AgentSecret `json:"credential"`
		ContextHint string      `json:"_note"`
	}
	writeJSON(w, http.StatusCreated, response{
		Agent:       agent,
		Credential:  secret,
		ContextHint: "Save the credential.secret value now: it is shown exactly once.",
	})
}

func (a *TheAuth) adminPatchAgent(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	agentID, ok := parseULIDPath(r, "agentID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid agentID", "")
		return
	}
	if err := a.ensureAgentInOrg(r, agentID, orgID); err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, err.Error(), "")
		return
	}
	var body struct {
		Status string `json:"status,omitempty"`
		Reason string `json:"reason,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	var err error
	switch body.Status {
	case AgentStatusSuspended:
		err = a.SuspendAgent(r.Context(), agentID, body.Reason)
	case AgentStatusActive:
		err = a.ResumeAgent(r.Context(), agentID)
	default:
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "status must be active or suspended", "")
		return
	}
	if err != nil {
		if errors.Is(err, ErrAgentInactive) {
			admin.Write(w, http.StatusConflict, admin.CodeValidationInvalid, err.Error(), "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	ag, err := a.GetAgent(r.Context(), agentID)
	if err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, ag)
}

func (a *TheAuth) adminDeleteAgent(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	agentID, ok := parseULIDPath(r, "agentID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid agentID", "")
		return
	}
	if err := a.ensureAgentInOrg(r, agentID, orgID); err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, err.Error(), "")
		return
	}
	reason := r.URL.Query().Get("reason")
	if err := a.RevokeAgent(r.Context(), agentID, reason); err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- delegations ----------

func (a *TheAuth) adminListDelegations(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	// Filter by user_id or agent_id when supplied; otherwise list every
	// delegation grant for any user-member of the organization. The Storage
	// surface exposes per-user and per-agent listings; admins must pass one.
	userIDStr := r.URL.Query().Get("user_id")
	agentIDStr := r.URL.Query().Get("agent_id")
	if userIDStr == "" && agentIDStr == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "user_id or agent_id query param required", "")
		return
	}
	var grants []DelegationGrant
	var err error
	if userIDStr != "" {
		id, perr := ulid.Parse(userIDStr)
		if perr != nil {
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid user_id", "")
			return
		}
		grants, err = a.ListDelegationsForUser(r.Context(), id)
	} else {
		id, perr := ulid.Parse(agentIDStr)
		if perr != nil {
			admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid agent_id", "")
			return
		}
		grants, err = a.ListDelegationsForAgent(r.Context(), id)
	}
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	// Filter to grants scoped to this org. Grants with OrganizationID nil
	// belong to the user's personal scope and are excluded from org admin
	// listings.
	out := grants[:0]
	for _, g := range grants {
		if g.OrganizationID != nil && *g.OrganizationID == orgID {
			out = append(out, g)
		}
	}
	type response struct {
		Delegations []DelegationGrant `json:"delegations"`
		Next        string            `json:"next,omitempty"`
	}
	writeJSON(w, http.StatusOK, response{Delegations: out})
}

func (a *TheAuth) adminCreateDelegation(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	var body struct {
		UserID             string    `json:"userId"`
		AgentID            string    `json:"agentId"`
		Scope              []string  `json:"scope"`
		Resource           string    `json:"resource"`
		MaxDurationSeconds int       `json:"maxDurationSeconds"`
		ExpiresAt          time.Time `json:"expiresAt,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil {
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
	// security audit H3 (2026-06-20): the body.UserID was previously
	// trusted blindly. Without this check an admin in any org could mint
	// a delegation_grant naming any user in the system, with no consent
	// from the named user. The grant remained usable for token exchange
	// because DelegationGrantByUserAgentResource does not filter by org.
	// Verify the named user is a member of the calling admin's org
	// before persisting; reject with 403 problem+json otherwise.
	if _, err := a.storage.OrganizationMemberRole(r.Context(), orgID, userID); err != nil {
		admin.Write(w, http.StatusForbidden, admin.CodeUserNotInOrg, "user is not a member of this organization", "")
		return
	}
	orgIDCp := orgID
	in := GrantDelegationInput{
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
	grant, err := a.GrantDelegation(r.Context(), in)
	if err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	writeJSON(w, http.StatusCreated, grant)
}

func (a *TheAuth) adminRevokeDelegation(w http.ResponseWriter, r *http.Request) {
	orgID, _ := parseULIDPath(r, "orgID")
	grantID, ok := parseULIDPath(r, "grantID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid grantID", "")
		return
	}
	grant, err := a.delegationSvc.GrantByID(r.Context(), grantID)
	if err != nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "delegation grant not found", "")
		return
	}
	if grant.OrganizationID == nil || *grant.OrganizationID != orgID {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "delegation grant not found in this organization", "")
		return
	}
	reason := r.URL.Query().Get("reason")
	if err := a.RevokeDelegation(r.Context(), grantID, reason); err != nil {
		if errors.Is(err, ErrDelegationNotFound) {
			admin.Write(w, http.StatusNotFound, admin.CodeNotFound, err.Error(), "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ensureAgentInOrg returns an error when the supplied agent ID is not owned
// by the supplied organization. Used by the admin patch + delete paths so
// cross-org tampering returns 404 (no leak of agent existence).
func (a *TheAuth) ensureAgentInOrg(r *http.Request, agentID, orgID ULID) error {
	ag, err := a.agentSvc.AgentByID(r.Context(), agentID)
	if err != nil {
		return errors.New("agent not found")
	}
	if ag.OrganizationID == nil || *ag.OrganizationID != orgID {
		return errors.New("agent not found in this organization")
	}
	return nil
}
