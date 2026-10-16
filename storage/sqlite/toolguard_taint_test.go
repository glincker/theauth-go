package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/policy/toolguard"
)

// A tainted tool call lands in the signed audit chain with its labels and the
// taint verdict as input provenance, and the chain still verifies.
func TestToolGuardProvenanceInAuditChain(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	if err := sqlitestore.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := sqlitestore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		CoreStorage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		Audit:                       &theauth.AuditConfig{},
		SuppressSecureCookieWarning: true, SuppressTrustedProxiesWarning: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	doc, err := policy.Parse([]byte(`{"version":"1","statements":[{"effect":"allow","actions":["execute"],"resources":["tool:*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	g := &toolguard.Guard{
		Evaluator: policy.Evaluator{Taint: []policy.TaintRule{{
			ID: "mail-recipient", Resource: "tool:send_email",
			Args: map[string]policy.ArgRule{"recipient": {Forbid: []string{"untrusted_web"}}},
		}}},
		Policies:  func(context.Context, string) ([]*policy.Policy, error) { return []*policy.Policy{doc}, nil },
		Approvals: toolguard.NewMemoryApprovals(),
		Audit:     a.EmitAudit,
	}
	err = g.Authorize(ctx, toolguard.Call{AgentID: "agent_1", Tool: "send_email",
		Provenance: map[string][]string{"recipient": {"untrusted_web"}, "body": {"user"}}})
	if !errors.Is(err, toolguard.ErrApprovalRequired) {
		t.Fatalf("want escalation, got %v", err)
	}
	if err := g.Authorize(ctx, toolguard.Call{AgentID: "agent_1", Tool: "send_email"}); err != nil {
		t.Fatal(err)
	}
	a.Close()

	evs, _, err := store.QueryAuditEvents(ctx, theauth.AuditQuery{Action: "agent.authorize"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 record (the unlabeled call emits none), got %d", len(evs))
	}
	e := evs[0]
	labels, _ := e.InputProvenance["labels"].(map[string]any)
	taint, _ := e.InputProvenance["taint"].(map[string]any)
	if rl, _ := labels["recipient"].([]any); len(rl) != 1 || rl[0] != "untrusted_web" {
		t.Fatalf("labels lost: %+v", e.InputProvenance)
	}
	if taint["verdict"] != "escalate" || e.ActorID != "agent_1" || e.Metadata["outcome"] != "approval_required" {
		t.Fatalf("verdict or actor lost: %+v actor=%q meta=%+v", taint, e.ActorID, e.Metadata)
	}
	res, err := store.VerifyAuditChain(ctx)
	if err != nil || !res.OK || res.Checked < 1 {
		t.Fatalf("chain verify = %+v, %v", res, err)
	}
}
