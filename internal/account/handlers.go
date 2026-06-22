// Package account exposes the /account/* end-user self-service
// endpoints (agents the user owns and delegation grants the user has
// issued). Extracted from root handlers_account.go in PR F of the
// 2026-06 architecture reorg. Collapsed from internal/account/handlers
// into internal/account in PR H (2026-06-22): the handlers/ subdir
// was the only child so the extra nesting added no value.
//
// Every route is session-gated via the RequireAuth middleware
// supplied at Mount time; no special permission is required because
// every action is scoped to the calling user's own records.
package account

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

// AgentService is the subset of the agent service the account
// handler needs. Implemented by root *TheAuth so this package does
// not import root.
type AgentService interface {
	ListAgentsByOwner(ctx context.Context, owner models.AgentOwner) ([]models.Agent, error)
	CreateAgent(ctx context.Context, in models.CreateAgentInput) (models.Agent, models.AgentSecret, error)
	AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error)
	RevokeAgent(ctx context.Context, agentID models.ULID, reason string) error
}

// DelegationService is the subset of the delegation service the
// account handler needs.
type DelegationService interface {
	ListDelegationsForUser(ctx context.Context, userID models.ULID) ([]models.DelegationGrant, error)
	GrantDelegation(ctx context.Context, in models.GrantDelegationInput) (models.DelegationGrant, error)
	GrantByID(ctx context.Context, grantID models.ULID) (*models.DelegationGrant, error)
	RevokeDelegation(ctx context.Context, grantID models.ULID, reason string) error
}

// UserFromCtx pulls the authenticated user out of the request
// context (every endpoint here runs through RequireAuth).
type UserFromCtx func(r *http.Request) (*models.User, bool)

// Handler owns the six /account/* endpoints.
type Handler struct {
	agents      AgentService
	delegations DelegationService
	userFromCtx UserFromCtx
}

// New constructs a Handler.
func New(agents AgentService, delegations DelegationService, userFromCtx UserFromCtx) *Handler {
	return &Handler{agents: agents, delegations: delegations, userFromCtx: userFromCtx}
}

// Mount wires /account/* under r. requireAuth is supplied by root
// since the session middleware owns the cookie / RBAC plumbing.
func (h *Handler) Mount(r chi.Router, requireAuth func(http.Handler) http.Handler) {
	r.Route("/account", func(r chi.Router) {
		r.Use(requireAuth)
		r.Get("/agents", h.listAgents)
		r.Post("/agents", h.createAgent)
		r.Delete("/agents/{agentID}", h.revokeAgent)
		r.Get("/delegations", h.listDelegations)
		r.Post("/delegations", h.createDelegation)
		r.Post("/delegations/{grantID}/revoke", h.revokeDelegation)
	})
}

// ---------- agents ----------

func (h *Handler) listAgents(w http.ResponseWriter, r *http.Request) {
	user, ok := h.userFromCtx(r)
	if !ok || user == nil {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}
	uid := user.ID
	agents, err := h.agents.ListAgentsByOwner(r.Context(), models.AgentOwner{UserID: &uid})
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
	user, ok := h.userFromCtx(r)
	if !ok || user == nil {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}
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
	uid := user.ID
	agent, secret, err := h.agents.CreateAgent(r.Context(), models.CreateAgentInput{
		Owner:       models.AgentOwner{UserID: &uid},
		Name:        body.Name,
		Description: body.Description,
		Scope:       body.Scope,
	})
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

func (h *Handler) revokeAgent(w http.ResponseWriter, r *http.Request) {
	user, ok := h.userFromCtx(r)
	if !ok || user == nil {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}
	agentID, ok := httpx.ParseULIDPath(r, "agentID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid agentID", "")
		return
	}
	ag, err := h.agents.AgentByID(r.Context(), agentID)
	if err != nil || ag == nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "agent not found", "")
		return
	}
	if ag.OwnerUserID == nil || *ag.OwnerUserID != user.ID {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "agent not found", "")
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
	user, ok := h.userFromCtx(r)
	if !ok || user == nil {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}
	grants, err := h.delegations.ListDelegationsForUser(r.Context(), user.ID)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	type response struct {
		Delegations []models.DelegationGrant `json:"delegations"`
		Next        string                   `json:"next,omitempty"`
	}
	httpx.WriteJSON(w, http.StatusOK, response{Delegations: grants})
}

func (h *Handler) createDelegation(w http.ResponseWriter, r *http.Request) {
	user, ok := h.userFromCtx(r)
	if !ok || user == nil {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}
	var body struct {
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
	agentID, err := ulid.Parse(body.AgentID)
	if err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid agentId", "")
		return
	}
	in := models.GrantDelegationInput{
		UserID:             user.ID,
		AgentID:            agentID,
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
	user, ok := h.userFromCtx(r)
	if !ok || user == nil {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}
	grantID, ok := httpx.ParseULIDPath(r, "grantID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid grantID", "")
		return
	}
	grant, err := h.delegations.GrantByID(r.Context(), grantID)
	if err != nil || grant == nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "delegation grant not found", "")
		return
	}
	if grant.UserID != user.ID {
		// Cross-user revocation is forbidden: only the granting user (or
		// an org admin via /admin/v1) can revoke. Return 404 to avoid
		// leaking grant existence.
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "delegation grant not found", "")
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
