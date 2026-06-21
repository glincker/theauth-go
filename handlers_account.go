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

// handlers_account.go: end-user self-service routes for managing agents and
// delegation grants the authenticated user owns. Mounted at /account/* when
// Config.AccountUX is true (and AgentIdentity is configured). Auth: session
// cookie via RequireAuth; no special permission, because every action is
// scoped to the user's own records.

// mountAccount wires the /account routes. Idempotent guard so callers who
// repeat Mount do not double-register.
func (a *TheAuth) mountAccount(r chi.Router) {
	if !a.accountUX || a.agentCfg == nil || a.as == nil {
		return
	}
	r.Route("/account", func(r chi.Router) {
		r.Use(a.RequireAuth())
		r.Get("/agents", a.accountListAgents)
		r.Post("/agents", a.accountCreateAgent)
		r.Delete("/agents/{agentID}", a.accountRevokeAgent)
		r.Get("/delegations", a.accountListDelegations)
		r.Post("/delegations", a.accountCreateDelegation)
		r.Post("/delegations/{grantID}/revoke", a.accountRevokeDelegation)
	})
}

// ---------- agents ----------

func (a *TheAuth) accountListAgents(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok || user == nil {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}
	uid := user.ID
	owner := AgentOwner{UserID: &uid}
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

func (a *TheAuth) accountCreateAgent(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok || user == nil {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}
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
	uid := user.ID
	agent, secret, err := a.CreateAgent(r.Context(), CreateAgentInput{
		Owner:       AgentOwner{UserID: &uid},
		Name:        body.Name,
		Description: body.Description,
		Scope:       body.Scope,
	})
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

func (a *TheAuth) accountRevokeAgent(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok || user == nil {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}
	agentID, ok := parseULIDPath(r, "agentID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid agentID", "")
		return
	}
	ag, err := a.oauthStorage.AgentByID(r.Context(), agentID)
	if err != nil || ag == nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "agent not found", "")
		return
	}
	if ag.OwnerUserID == nil || *ag.OwnerUserID != user.ID {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "agent not found", "")
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

func (a *TheAuth) accountListDelegations(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok || user == nil {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}
	grants, err := a.ListDelegationsForUser(r.Context(), user.ID)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	type response struct {
		Delegations []DelegationGrant `json:"delegations"`
		Next        string            `json:"next,omitempty"`
	}
	writeJSON(w, http.StatusOK, response{Delegations: grants})
}

func (a *TheAuth) accountCreateDelegation(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
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
	if err := decodeJSON(r, &body); err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	agentID, err := ulid.Parse(body.AgentID)
	if err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid agentId", "")
		return
	}
	in := GrantDelegationInput{
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
	grant, err := a.GrantDelegation(r.Context(), in)
	if err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	writeJSON(w, http.StatusCreated, grant)
}

func (a *TheAuth) accountRevokeDelegation(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok || user == nil {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}
	grantID, ok := parseULIDPath(r, "grantID")
	if !ok {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid grantID", "")
		return
	}
	grant, err := a.oauthStorage.DelegationGrantByID(r.Context(), grantID)
	if err != nil || grant == nil {
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "delegation grant not found", "")
		return
	}
	if grant.UserID != user.ID {
		// Cross-user revocation is forbidden: only the granting user (or an
		// org admin via /admin/v1) can revoke. Return 404 to avoid leaking
		// grant existence.
		admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "delegation grant not found", "")
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
