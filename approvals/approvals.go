// Package approvals is a small HTTP inbox for agent tool approvals: list pending
// requests, approve or deny them, with a four-eyes rule and an audit row per decision.
package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/admin"
	"github.com/glincker/theauth-go/v2/audit"
)

// MaxArgumentBytes caps the JSON size of the redacted arguments in a response.
const MaxArgumentBytes = 2048

// Audit actions written for each decision.
const (
	ActionApproved = "tool_approval.approved"
	ActionDenied   = "tool_approval.denied"
)

// Status values for ?status= and the "status" response field.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
	StatusSpent    = "consumed"
)

// Config wires the handler. Store, Audit, Authenticate and IsAdmin are required.
type Config struct {
	Store theauth.ToolApprovalAdminStorage
	Audit theauth.AuditStorage
	// Authenticate resolves the caller from the request (your session or token check). An error
	// means unauthenticated (401).
	Authenticate func(*http.Request) (adminID string, err error)
	// IsAdmin reports whether adminID may decide approvals. false means 403.
	IsAdmin func(ctx context.Context, adminID string) bool
	// AllowSelfApproval lets the admin who opened a request decide it. Default false (four-eyes).
	AllowSelfApproval bool
	// Arguments optionally supplies the tool call arguments to show for a request. They are
	// redacted and truncated to MaxArgumentBytes before they leave the handler.
	Arguments func(theauth.ToolApproval) map[string]any
	// Now overrides the clock in tests.
	Now func() time.Time
}

// View is one approval as returned over HTTP.
type View struct {
	ID        string         `json:"id"`
	AgentID   string         `json:"agentId"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Reason    string         `json:"reason,omitempty"`
	Status    string         `json:"status"`
	OpenedBy  string         `json:"openedBy,omitempty"`
	DecidedBy string         `json:"decidedBy,omitempty"`
	CreatedAt time.Time      `json:"createdAt"`
	ExpiresAt *time.Time     `json:"expiresAt,omitempty"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ErrConfig is returned by New for a missing required field.
var ErrConfig = errors.New("approvals: Store, Audit, Authenticate and IsAdmin are required")

type handler struct{ cfg Config }

// New returns a handler serving GET /approvals, POST /approvals/{id}/approve and
// POST /approvals/{id}/deny. Mount it at the root or behind http.StripPrefix.
func New(cfg Config) (http.Handler, error) {
	if cfg.Store == nil || cfg.Audit == nil || cfg.Authenticate == nil || cfg.IsAdmin == nil {
		return nil, ErrConfig
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	h := &handler{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /approvals", h.guard(h.list))
	mux.HandleFunc("POST /approvals/{id}/approve", h.guard(h.decide(true)))
	mux.HandleFunc("POST /approvals/{id}/deny", h.guard(h.decide(false)))
	return mux, nil
}

type adminHandler func(w http.ResponseWriter, r *http.Request, adminID string)

func (h *handler) guard(next adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adminID, err := h.cfg.Authenticate(r)
		if err != nil || adminID == "" {
			admin.Write(w, http.StatusUnauthorized, "approvals.unauthenticated", "authentication required", r.URL.Path)
			return
		}
		if !h.cfg.IsAdmin(r.Context(), adminID) {
			admin.Write(w, http.StatusForbidden, "approvals.forbidden", "admin role required", r.URL.Path)
			return
		}
		next(w, r, adminID)
	}
}

func statusOf(a theauth.ToolApproval, now time.Time) string {
	switch {
	case !a.DeniedAt.IsZero():
		return StatusDenied
	case !a.ConsumedAt.IsZero():
		return StatusSpent
	case !a.ApprovedAt.IsZero():
		return StatusApproved
	case !a.ExpiresAt.IsZero() && !a.ExpiresAt.After(now):
		return StatusExpired
	default:
		return StatusPending
	}
}

func (h *handler) view(a theauth.ToolApproval, now time.Time) View {
	v := View{
		ID: a.ID, AgentID: a.AgentID, Action: a.Action, Resource: truncate(a.Resource),
		Reason: truncate(a.Reason), Status: statusOf(a, now), OpenedBy: a.OpenedBy, CreatedAt: a.CreatedAt,
	}
	if !a.ExpiresAt.IsZero() {
		e := a.ExpiresAt
		v.ExpiresAt = &e
	}
	switch {
	case a.DeniedBy != "":
		v.DecidedBy = a.DeniedBy
	case a.Approver != "":
		v.DecidedBy = a.Approver
	}
	if h.cfg.Arguments != nil {
		v.Arguments = RedactArguments(h.cfg.Arguments(a))
	}
	return v
}

func (h *handler) list(w http.ResponseWriter, r *http.Request, _ string) {
	want := r.URL.Query().Get("status")
	switch want {
	case "", StatusPending, StatusApproved, StatusDenied, StatusExpired, StatusSpent:
	default:
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "unknown status", r.URL.Path)
		return
	}
	all, err := h.cfg.Store.ListToolApprovals(r.Context(), 0)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, "approvals.internal", "list failed", r.URL.Path)
		return
	}
	now := h.cfg.Now()
	out := make([]View, 0, len(all))
	for _, a := range all {
		if v := h.view(a, now); want == "" || v.Status == want {
			out = append(out, v)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": out})
}

func (h *handler) decide(approve bool) adminHandler {
	return func(w http.ResponseWriter, r *http.Request, adminID string) {
		ctx, id, now := r.Context(), r.PathValue("id"), h.cfg.Now()
		a, ok, err := h.cfg.Store.GetToolApproval(ctx, id)
		if err != nil {
			admin.Write(w, http.StatusInternalServerError, "approvals.internal", "lookup failed", r.URL.Path)
			return
		}
		if !ok {
			admin.Write(w, http.StatusNotFound, admin.CodeNotFound, "approval not found", r.URL.Path)
			return
		}
		if !h.cfg.AllowSelfApproval && a.OpenedBy != "" && a.OpenedBy == adminID {
			admin.Write(w, http.StatusForbidden, "approvals.self_approval", "the requester cannot decide their own request", r.URL.Path)
			return
		}
		if statusOf(a, now) != StatusPending {
			admin.Write(w, http.StatusConflict, "approvals.not_pending", "approval is not pending", r.URL.Path)
			return
		}
		action := ActionDenied
		if approve {
			action = ActionApproved
			ok, err = h.cfg.Store.ApproveToolApproval(ctx, id, adminID, now)
		} else {
			ok, err = h.cfg.Store.DenyToolApproval(ctx, id, adminID, now)
		}
		if err != nil {
			admin.Write(w, http.StatusInternalServerError, "approvals.internal", "decision failed", r.URL.Path)
			return
		}
		if !ok {
			admin.Write(w, http.StatusConflict, "approvals.not_pending", "approval was already decided", r.URL.Path)
			return
		}
		md := map[string]any{"action": a.Action, "resource": truncate(a.Resource)}
		if err := h.cfg.Audit.InsertAuditEvents(ctx, []theauth.AuditEvent{{
			ID: ulid.Make(), Action: action, Event: audit.EventForAction(action), TargetType: "tool_approval", TargetID: id,
			SubjectID: a.AgentID, ActorID: adminID, ApproverID: adminID, Metadata: md, CreatedAt: now,
		}}); err != nil {
			admin.Write(w, http.StatusInternalServerError, "approvals.audit_failed", "decision recorded but audit write failed", r.URL.Path)
			return
		}
		fresh, _, _ := h.cfg.Store.GetToolApproval(ctx, id)
		writeJSON(w, http.StatusOK, h.view(fresh, now))
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

const truncMarker = "...[truncated]"

func truncate(s string) string {
	if len(s) <= MaxArgumentBytes {
		return s
	}
	return strings.ToValidUTF8(s[:MaxArgumentBytes], "") + truncMarker
}

var secretFragments = []string{"password", "passwd", "secret", "token", "key", "auth", "cookie", "credential", "session", "bearer", "signature", "code"}

func secretKey(k string) bool {
	l := strings.ToLower(k)
	for _, f := range secretFragments {
		if strings.Contains(l, f) {
			return true
		}
	}
	return false
}

func redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if secretKey(k) {
				out[k] = "[REDACTED]"
			} else {
				out[k] = redact(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redact(e)
		}
		return out
	default:
		return v
	}
}

// RedactArguments masks values under secret-looking keys (any key containing password, secret,
// token, key, auth, cookie, credential, session, bearer, signature or code) at any depth, and
// returns a copy. If the JSON form exceeds MaxArgumentBytes it is replaced by a map holding a
// truncated "_truncated" preview. The input is not modified.
func RedactArguments(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out, _ := redact(in).(map[string]any)
	b, err := json.Marshal(out)
	if err != nil {
		return map[string]any{"_error": "arguments not serializable"}
	}
	if len(b) <= MaxArgumentBytes {
		return out
	}
	return map[string]any{"_truncated": truncate(string(b))}
}
