package toolguard

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/policy"
)

// Event types sent to the StorageApprovals event sink and the webhook.
const (
	EventApprovalPending  = "approval.pending"
	EventApprovalApproved = "approval.approved"
	EventApprovalDenied   = "approval.denied"
	EventApprovalExpired  = "approval.expired"
)

// Audit actions StorageApprovals writes through its audit function. The first three also exist
// in the inbox (package approvals) and the shared event vocabulary maps them to approval.request,
// approval.approve and approval.deny. Expiry and consumption have no shared event and keep a
// NULL event column, which the audit design prefers to inventing names only one SDK knows.
const (
	AuditApprovalRequest  = "approval.request"
	AuditApprovalApproved = "tool_approval.approved"
	AuditApprovalDenied   = "tool_approval.denied"
	AuditApprovalExpired  = "tool_approval.expired"
	AuditApprovalConsumed = "tool_approval.consumed"
)

// ApprovalEvent is one step of an approval's life: opened, approved, denied or expired. It
// carries a hash of the arguments, never the arguments.
type ApprovalEvent struct {
	Type          string
	Code          policy.DecisionCode
	ApprovalID    string
	AgentID       string
	Action        string
	Resource      string
	ArgumentsHash string
	// DecidedBy is the human who approved or denied. Empty for pending and expired.
	DecidedBy string
	ExpiresAt time.Time
	CreatedAt time.Time
	At        time.Time
}

// eventCodes mirrors the TypeScript decision event shape: pending is approval_pending, an
// approval is approval_granted, then approval_denied and approval_expired.
var eventCodes = map[string]policy.DecisionCode{
	EventApprovalPending:  policy.CodeApprovalPending,
	EventApprovalApproved: policy.CodeApprovalGranted,
	EventApprovalDenied:   policy.CodeApprovalDenied,
	EventApprovalExpired:  policy.CodeApprovalExpired,
}

// AuditFunc records one audit row. (*theauth.TheAuth).EmitAudit fits.
type AuditFunc = func(ctx context.Context, action string, target theauth.TargetRef, metadata map[string]any)

func (a *StorageApprovals) emit(typ string, ap theauth.ToolApproval, decidedBy string) {
	if a.onEvent == nil {
		return
	}
	ev := ApprovalEvent{
		Type: typ, Code: eventCodes[typ], ApprovalID: ap.ID, AgentID: ap.AgentID, Action: ap.Action,
		Resource: ap.Resource, ArgumentsHash: ap.ArgumentsHash, DecidedBy: decidedBy,
		ExpiresAt: ap.ExpiresAt, CreatedAt: ap.CreatedAt, At: a.now().UTC(),
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Error("toolguard: approval event sink panicked", "event", typ, "panic", r)
		}
	}()
	a.onEvent(ev)
}

// record writes one audit row. A failed or missing audit never fails the approval step, which
// is already committed in the store.
func (a *StorageApprovals) record(ctx context.Context, action string, ap theauth.ToolApproval, actor, approver string) {
	if a.audit == nil {
		return
	}
	md, _ := audit.MetadataFromContext(ctx)
	md.SubjectID = ap.AgentID
	if actor != "" {
		md.ActorID = actor
	} else {
		md.ActorID = ap.AgentID
	}
	if approver != "" {
		md.ApproverID = approver
	}
	meta := map[string]any{"approval_id": ap.ID, "action": ap.Action, "resource": ap.Resource}
	defer func() {
		if r := recover(); r != nil {
			slog.Error("toolguard: approval audit function panicked", "action", action, "panic", r)
		}
	}()
	a.audit(audit.WithAuditMetadata(ctx, md), action, theauth.TargetRef{Type: "tool_approval", ID: ap.ID}, meta)
}

// WebhookConfig configures NewApprovalWebhook.
type WebhookConfig struct {
	// URL receives a JSON POST per event. It must be http or https. It is operator supplied
	// configuration: never build it from request data.
	URL string
	// Secret, when set, signs the body: header X-TheAuth-Signature is "sha256=" plus the hex
	// HMAC-SHA256 of the raw body.
	Secret []byte
	// Types limits which events are sent. Empty means only approval.pending.
	Types []string
	// Client defaults to a client with a 5 second timeout.
	Client *http.Client
}

type webhookBody struct {
	Event string         `json:"event"`
	Data  webhookPayload `json:"data"`
}

type webhookPayload struct {
	ApprovalID    string `json:"approvalId"`
	AgentID       string `json:"agentId"`
	Action        string `json:"action"`
	Resource      string `json:"resource"`
	ArgumentsHash string `json:"argumentsHash"`
	Code          string `json:"code"`
	DecidedBy     string `json:"decidedBy,omitempty"`
	ExpiresAt     string `json:"expiresAt,omitempty"`
	CreatedAt     string `json:"createdAt"`
}

// ErrWebhookURL is returned by NewApprovalWebhook for a missing or non http(s) URL.
var ErrWebhookURL = errors.New("toolguard: webhook URL must be an absolute http or https URL")

// NewApprovalWebhook returns an event sink for WithApprovalEvents that POSTs events to a URL.
// Delivery is asynchronous and best effort: a slow or failing endpoint never delays or fails the
// approval, which is already stored. The body carries a hash of the arguments, never the
// arguments.
func NewApprovalWebhook(cfg WebhookConfig) (func(ApprovalEvent), error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, ErrWebhookURL
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	want := map[string]bool{}
	for _, t := range cfg.Types {
		want[t] = true
	}
	if len(want) == 0 {
		want[EventApprovalPending] = true
	}
	return func(ev ApprovalEvent) {
		if !want[ev.Type] {
			return
		}
		go deliverWebhook(client, cfg.URL, cfg.Secret, ev)
	}, nil
}

func deliverWebhook(client *http.Client, target string, secret []byte, ev ApprovalEvent) {
	p := webhookPayload{
		ApprovalID: ev.ApprovalID, AgentID: ev.AgentID, Action: ev.Action, Resource: ev.Resource,
		ArgumentsHash: ev.ArgumentsHash, Code: string(ev.Code), DecidedBy: ev.DecidedBy,
		CreatedAt: ev.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if !ev.ExpiresAt.IsZero() {
		p.ExpiresAt = ev.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	body, err := json.Marshal(webhookBody{Event: ev.Type, Data: p})
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if len(secret) > 0 {
		m := hmac.New(sha256.New, secret)
		m.Write(body)
		req.Header.Set("X-TheAuth-Signature", "sha256="+hex.EncodeToString(m.Sum(nil)))
	}
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("toolguard: approval webhook failed", "event", ev.Type, "err", err.Error())
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		slog.Warn("toolguard: approval webhook rejected", "event", ev.Type, "status", fmt.Sprint(resp.StatusCode))
	}
}
