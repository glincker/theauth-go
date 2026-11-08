package approvals

import (
	"net/http"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/admin"
	"github.com/glincker/theauth-go/v2/audit"
)

// vote counts adminID's approval on a request that needs more than one approver. The request
// stays pending until the last approver acts, and each approval writes its own audit row with
// the quorum progress. A repeat approver gets 409, and so does a request that was decided or
// expired meanwhile. The store makes the count atomic, so two calls by one admin count once.
func (h *handler) vote(w http.ResponseWriter, r *http.Request, a theauth.ToolApproval, adminID string, now time.Time) {
	ctx := r.Context()
	q, ok := h.cfg.Store.(theauth.ToolApprovalQuorumStorage)
	if !ok {
		admin.Write(w, http.StatusNotImplemented, "approvals.quorum_unsupported", "the store does not support quorum approvals", r.URL.Path)
		return
	}
	res, err := q.VoteToolApproval(ctx, a.ID, adminID, now)
	if err != nil {
		admin.Write(w, http.StatusInternalServerError, "approvals.internal", "decision failed", r.URL.Path)
		return
	}
	switch res.Outcome {
	case theauth.VoteRequester:
		admin.Write(w, http.StatusForbidden, "approvals.self_approval", "the requester cannot decide their own request", r.URL.Path)
		return
	case theauth.VoteDuplicate:
		admin.Write(w, http.StatusConflict, "approvals.duplicate_approver", "this admin already approved the request", r.URL.Path)
		return
	case theauth.VoteNotPending:
		admin.Write(w, http.StatusConflict, "approvals.not_pending", "approval was already decided", r.URL.Path)
		return
	}
	md := map[string]any{
		"action": a.Action, "resource": truncate(a.Resource),
		"approvals_received": len(res.Approvers), "approvals_required": a.RequiredApprovals,
		"quorum_complete": res.Outcome == theauth.VoteCompleted,
	}
	if err := h.cfg.Audit.InsertAuditEvents(ctx, []theauth.AuditEvent{{
		ID: ulid.Make(), Action: ActionApproved, Event: audit.EventForAction(ActionApproved), TargetType: "tool_approval", TargetID: a.ID,
		SubjectID: a.AgentID, ActorID: adminID, ApproverID: adminID, Metadata: md, CreatedAt: now,
	}}); err != nil {
		admin.Write(w, http.StatusInternalServerError, "approvals.audit_failed", "decision recorded but audit write failed", r.URL.Path)
		return
	}
	fresh, _, _ := h.cfg.Store.GetToolApproval(ctx, a.ID)
	writeJSON(w, http.StatusOK, h.view(fresh, now))
}
