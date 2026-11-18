package toolguard

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func TestHashApprovalAction(t *testing.T) {
	t.Parallel()
	type pay struct {
		To     string  `json:"to"`
		Amount float64 `json:"amount"`
	}
	h := func(args any) string {
		t.Helper()
		out, err := HashApprovalAction("execute", "tool:pay", args)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	base := h(map[string]any{"to": "bob", "amount": 5})
	same := []struct {
		name string
		args any
	}{
		{"struct equals map", pay{To: "bob", Amount: 5}},
		{"key order", map[string]any{"amount": 5, "to": "bob"}},
		{"reserved prefix dropped", map[string]any{"to": "bob", "amount": 5, "theauthHook": "allow", "TheAuthX": 1}},
		{"approvalId dropped", map[string]any{"to": "bob", "amount": 5, "approvalId": "x", "inputProvenance": "y"}},
	}
	for _, tc := range same {
		if got := h(tc.args); got != base {
			t.Errorf("%s: hash differs", tc.name)
		}
	}
	if h(nil) != h(map[string]any{}) {
		t.Error("nil and empty object must hash the same")
	}
	for name, args := range map[string]any{
		"other value": map[string]any{"to": "eve", "amount": 5},
		"extra key":   map[string]any{"to": "bob", "amount": 5, "note": "x"},
		"nested":      map[string]any{"to": "bob", "amount": map[string]any{"v": 5}},
	} {
		if h(args) == base {
			t.Errorf("%s: hash must differ", name)
		}
	}
	if a, _ := HashApprovalAction("execute", "tool:pay", nil); a == func() string { b, _ := HashApprovalAction("read", "tool:pay", nil); return b }() {
		t.Error("action must be part of the hash")
	}
	if _, err := HashApprovalAction("a", "r", map[string]any{"c": make(chan int)}); err == nil {
		t.Error("unencodable arguments must return an error")
	}
}

func TestMemoryApprovalSpendCodes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	call := Call{AgentID: "a1", Tool: "pay", Args: map[string]any{"to": "bob", "amount": 5}}
	open := func(t *testing.T, m *MemoryApprovals) string {
		t.Helper()
		id, err := m.Open(ctx, call, policy.Escalation{Requirement: policy.RequireApproval})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	tests := []struct {
		name  string
		setup func(m *MemoryApprovals, id string)
		call  Call
		id    string
		want  policy.DecisionCode
	}{
		{"consumed", func(m *MemoryApprovals, id string) { _ = m.Approve(id, "boss") }, call, "", policy.CodeApprovalConsumed},
		{"not found", func(*MemoryApprovals, string) {}, call, "nope", policy.CodeApprovalNotFound},
		{"pending", func(*MemoryApprovals, string) {}, call, "", policy.CodeApprovalPending},
		{"denied", func(m *MemoryApprovals, id string) { _ = m.Deny(id, "boss") }, call, "", policy.CodeApprovalDenied},
		{"other agent", func(m *MemoryApprovals, id string) { _ = m.Approve(id, "boss") }, Call{AgentID: "a2", Tool: "pay", Args: call.Args}, "", policy.CodeApprovalMismatch},
		{"other tool", func(m *MemoryApprovals, id string) { _ = m.Approve(id, "boss") }, Call{AgentID: "a1", Tool: "refund", Args: call.Args}, "", policy.CodeApprovalMismatch},
		{"other arguments", func(m *MemoryApprovals, id string) { _ = m.Approve(id, "boss") }, Call{AgentID: "a1", Tool: "pay", Args: map[string]any{"to": "eve", "amount": 5}}, "", policy.CodeApprovalArgumentsMismatch},
		{"no arguments", func(m *MemoryApprovals, id string) { _ = m.Approve(id, "boss") }, Call{AgentID: "a1", Tool: "pay"}, "", policy.CodeApprovalArgumentsMismatch},
		{"unhashable arguments", func(m *MemoryApprovals, id string) { _ = m.Approve(id, "boss") }, Call{AgentID: "a1", Tool: "pay", Args: map[string]any{"c": make(chan int)}}, "", policy.CodeApprovalArgumentsMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := NewMemoryApprovals()
			id := open(t, m)
			tc.setup(m, id)
			if tc.id != "" {
				id = tc.id
			}
			got, err := m.Spend(ctx, id, tc.call)
			if err != nil || got != tc.want {
				t.Fatalf("Spend = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	t.Run("already used", func(t *testing.T) {
		t.Parallel()
		m := NewMemoryApprovals()
		id := open(t, m)
		_ = m.Approve(id, "boss")
		if code, _ := m.Spend(ctx, id, call); code != policy.CodeApprovalConsumed {
			t.Fatalf("first spend = %q", code)
		}
		if code, _ := m.Spend(ctx, id, call); code != policy.CodeApprovalAlreadyUsed {
			t.Fatalf("second spend = %q", code)
		}
		if err := m.Approve(id, "boss"); err == nil {
			t.Fatal("approve after spend succeeded")
		}
	})
	t.Run("deny after approve fails", func(t *testing.T) {
		t.Parallel()
		m := NewMemoryApprovals()
		id := open(t, m)
		_ = m.Approve(id, "boss")
		if err := m.Deny(id, "other"); err == nil {
			t.Fatal("deny after approve succeeded")
		}
	})
}

func TestGuardApprovalFlowCodes(t *testing.T) {
	t.Parallel()
	g, m := newGuard(t)
	ctx := context.Background()
	pay := func(to string) Call {
		return Call{AgentID: "a1", Tool: "pay", Amount: 500, Args: map[string]any{"to": to}}
	}
	askFor := func(t *testing.T, c Call) *ApprovalRequiredError {
		t.Helper()
		var are *ApprovalRequiredError
		if err := g.Authorize(ctx, c); !errors.As(err, &are) {
			t.Fatalf("want ApprovalRequiredError, got %v", err)
		}
		return are
	}
	first := askFor(t, pay("bob"))
	if err := m.Approve(first.ApprovalID, "boss"); err != nil {
		t.Fatal(err)
	}

	t.Run("different arguments open a fresh request", func(t *testing.T) {
		are := askFor2(t, WithApprovalID(ctx, first.ApprovalID), g, pay("eve"))
		if are.Code != policy.CodeApprovalArgumentsMismatch || are.ApprovalID == "" || are.ApprovalID == first.ApprovalID {
			t.Fatalf("got code %q id %q", are.Code, are.ApprovalID)
		}
	})
	t.Run("same arguments spend once", func(t *testing.T) {
		if err := g.Authorize(WithApprovalID(ctx, first.ApprovalID), pay("bob")); err != nil {
			t.Fatal(err)
		}
		are := askFor2(t, WithApprovalID(ctx, first.ApprovalID), g, pay("bob"))
		if are.Code != policy.CodeApprovalAlreadyUsed {
			t.Fatalf("replay code = %q", are.Code)
		}
	})
	t.Run("denied request is not reopened", func(t *testing.T) {
		d := askFor(t, pay("zed"))
		if err := m.Deny(d.ApprovalID, "boss"); err != nil {
			t.Fatal(err)
		}
		are := askFor2(t, WithApprovalID(ctx, d.ApprovalID), g, pay("zed"))
		if are.Code != policy.CodeApprovalDenied || are.ApprovalID != "" {
			t.Fatalf("got code %q id %q", are.Code, are.ApprovalID)
		}
	})
	t.Run("unknown id", func(t *testing.T) {
		are := askFor2(t, WithApprovalID(ctx, "nope"), g, pay("bob"))
		if are.Code != policy.CodeApprovalNotFound {
			t.Fatalf("code = %q", are.Code)
		}
	})
	t.Run("custom approvals without Spend keep approval_invalid", func(t *testing.T) {
		g2 := &Guard{Evaluator: g.Evaluator, Policies: g.Policies, Approvals: consumeOnly{m}}
		are := askFor2(t, WithApprovalID(ctx, "nope"), g2, pay("bob"))
		if are.Code != policy.CodeApprovalInvalid {
			t.Fatalf("code = %q", are.Code)
		}
	})
}

type consumeOnly struct{ m *MemoryApprovals }

func (c consumeOnly) Open(ctx context.Context, call Call, e policy.Escalation) (string, error) {
	return c.m.Open(ctx, call, e)
}

func (c consumeOnly) Consume(ctx context.Context, id string, call Call) (bool, error) {
	return c.m.Consume(ctx, id, call)
}

func askFor2(t *testing.T, ctx context.Context, g *Guard, c Call) *ApprovalRequiredError {
	t.Helper()
	var are *ApprovalRequiredError
	if err := g.Authorize(ctx, c); !errors.As(err, &are) {
		t.Fatalf("want ApprovalRequiredError, got %v", err)
	}
	return are
}

type recorder struct {
	mu     sync.Mutex
	audits []string
	events []ApprovalEvent
}

func (r *recorder) audit(_ context.Context, action string, _ theauth.TargetRef, _ map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.audits = append(r.audits, action)
}

func (r *recorder) event(e ApprovalEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) types() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.events))
	for i, e := range r.events {
		out[i] = e.Type
	}
	return out
}

func newStorageApprovals(now *time.Time, rec *recorder) *StorageApprovals {
	return NewStorageApprovals(memory.New(),
		WithApprovalClock(func() time.Time { return *now }),
		WithApprovalTTL(time.Minute),
		WithApprovalAudit(rec.audit),
		WithApprovalEvents(rec.event))
}

func TestStorageApprovalsDecide(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	call := Call{AgentID: "a1", Tool: "pay", Args: map[string]any{"to": "bob"}}
	esc := policy.Escalation{Requirement: policy.RequireApproval}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	t.Run("approve audits, announces and spends", func(t *testing.T) {
		rec := &recorder{}
		ap := newStorageApprovals(&now, rec)
		id, err := ap.Open(ctx, call, esc)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ap.Decide(ctx, id, DecideInput{Decision: DecisionApprove, DecidedBy: "alice"})
		if err != nil || got.Approver != "alice" || got.ApprovedAt.IsZero() {
			t.Fatalf("Decide = %+v, %v", got, err)
		}
		if code, err := ap.Spend(ctx, id, call); err != nil || code != policy.CodeApprovalConsumed {
			t.Fatalf("Spend = %q, %v", code, err)
		}
		if want := []string{AuditApprovalRequest, AuditApprovalApproved, AuditApprovalConsumed}; strings.Join(rec.audits, ",") != strings.Join(want, ",") {
			t.Fatalf("audits = %v, want %v", rec.audits, want)
		}
		if want := []string{EventApprovalPending, EventApprovalApproved}; strings.Join(rec.types(), ",") != strings.Join(want, ",") {
			t.Fatalf("events = %v, want %v", rec.types(), want)
		}
		if rec.events[0].Code != policy.CodeApprovalPending || rec.events[1].Code != policy.CodeApprovalGranted || rec.events[0].ArgumentsHash == "" {
			t.Fatalf("event shape = %+v", rec.events)
		}
	})
	t.Run("deny then spend reports denied", func(t *testing.T) {
		rec := &recorder{}
		ap := newStorageApprovals(&now, rec)
		id, _ := ap.Open(ctx, call, esc)
		if _, err := ap.Decide(ctx, id, DecideInput{Decision: DecisionDeny, DecidedBy: "alice"}); err != nil {
			t.Fatal(err)
		}
		if code, _ := ap.Spend(ctx, id, call); code != policy.CodeApprovalDenied {
			t.Fatalf("code = %q", code)
		}
		if _, err := ap.Decide(ctx, id, DecideInput{Decision: DecisionApprove, DecidedBy: "bob"}); !errors.Is(err, ErrApprovalNotPending) {
			t.Fatalf("approve after deny = %v", err)
		}
	})
	t.Run("input and lookup errors", func(t *testing.T) {
		ap := newStorageApprovals(&now, &recorder{})
		id, _ := ap.Open(ctx, call, esc)
		if _, err := ap.Decide(ctx, id, DecideInput{Decision: "maybe", DecidedBy: "a"}); !errors.Is(err, ErrDecisionInvalid) {
			t.Fatalf("bad decision = %v", err)
		}
		if _, err := ap.Decide(ctx, id, DecideInput{Decision: DecisionApprove}); !errors.Is(err, ErrDecidedByRequired) {
			t.Fatalf("no decidedBy = %v", err)
		}
		if _, err := ap.Decide(ctx, "nope", DecideInput{Decision: DecisionApprove, DecidedBy: "a"}); !errors.Is(err, ErrApprovalNotFound) {
			t.Fatalf("unknown = %v", err)
		}
	})
	t.Run("expired request cannot be decided and expires once", func(t *testing.T) {
		rec := &recorder{}
		clock := now
		ap := newStorageApprovals(&clock, rec)
		id, _ := ap.Open(ctx, call, esc)
		clock = now.Add(2 * time.Minute)
		for range 3 {
			if _, err := ap.Decide(ctx, id, DecideInput{Decision: DecisionApprove, DecidedBy: "alice"}); !errors.Is(err, ErrApprovalExpired) {
				t.Fatalf("decide after expiry = %v", err)
			}
		}
		if code, _ := ap.Spend(ctx, id, call); code != policy.CodeApprovalExpired {
			t.Fatalf("spend code = %q", code)
		}
		expired := 0
		for _, a := range rec.audits {
			if a == AuditApprovalExpired {
				expired++
			}
		}
		if expired != 1 || strings.Count(strings.Join(rec.types(), ","), EventApprovalExpired) != 1 {
			t.Fatalf("expiry announced %d times: audits %v events %v", expired, rec.audits, rec.types())
		}
	})
	t.Run("approved but unspent request expires", func(t *testing.T) {
		clock := now
		ap := newStorageApprovals(&clock, &recorder{})
		id, _ := ap.Open(ctx, call, esc)
		if err := ap.Approve(ctx, id, "alice"); err != nil {
			t.Fatal(err)
		}
		clock = now.Add(2 * time.Minute)
		if code, _ := ap.Spend(ctx, id, call); code != policy.CodeApprovalExpired {
			t.Fatalf("code = %q", code)
		}
	})
	t.Run("cleanup marks overdue once", func(t *testing.T) {
		rec := &recorder{}
		clock := now
		ap := newStorageApprovals(&clock, rec)
		for range 3 {
			if _, err := ap.Open(ctx, call, esc); err != nil {
				t.Fatal(err)
			}
		}
		clock = now.Add(time.Hour)
		if n, err := ap.Cleanup(ctx); err != nil || n != 3 {
			t.Fatalf("Cleanup = %d, %v", n, err)
		}
		if n, _ := ap.Cleanup(ctx); n != 0 {
			t.Fatalf("second Cleanup = %d", n)
		}
	})
	t.Run("unhashable arguments fail closed at open", func(t *testing.T) {
		ap := newStorageApprovals(&now, &recorder{})
		bad := Call{AgentID: "a1", Tool: "pay", Args: map[string]any{"c": make(chan int)}}
		if _, err := ap.Open(ctx, bad, esc); err == nil {
			t.Fatal("open with unhashable arguments succeeded")
		}
	})
}

func TestStorageApprovalsArgumentsAndLegacyRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memory.New()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	ap := NewStorageApprovals(store, WithApprovalClock(func() time.Time { return now }))
	call := Call{AgentID: "a1", Tool: "pay", Args: map[string]any{"to": "bob"}}
	id, _ := ap.Open(ctx, call, policy.Escalation{Requirement: policy.RequireApproval})
	_ = ap.Approve(ctx, id, "alice")
	other := Call{AgentID: "a1", Tool: "pay", Args: map[string]any{"to": "eve"}}
	if code, _ := ap.Spend(ctx, id, other); code != policy.CodeApprovalArgumentsMismatch {
		t.Fatalf("code = %q", code)
	}
	if code, _ := ap.Spend(ctx, id, call); code != policy.CodeApprovalConsumed {
		t.Fatalf("a mismatch must not burn the approval, got %q", code)
	}
	// A row opened before the hash column existed has no hash and covers any arguments.
	legacy := theauth.ToolApproval{ID: "legacy", AgentID: "a1", Action: "execute", Resource: "tool:pay", CreatedAt: now}
	if err := store.OpenToolApproval(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	_, _ = store.ApproveToolApproval(ctx, "legacy", "alice", now)
	if code, _ := ap.Spend(ctx, "legacy", other); code != policy.CodeApprovalConsumed {
		t.Fatalf("legacy row code = %q", code)
	}
}

func TestStorageApprovalsConcurrentSpendCodes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ap := NewStorageApprovals(memory.New())
	call := Call{AgentID: "a1", Tool: "pay", Args: map[string]any{"to": "bob"}}
	id, _ := ap.Open(ctx, call, policy.Escalation{Requirement: policy.RequireApproval})
	_ = ap.Approve(ctx, id, "alice")
	var wins, used atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			switch code, err := ap.Spend(ctx, id, call); {
			case err != nil:
				t.Error(err)
			case code == policy.CodeApprovalConsumed:
				wins.Add(1)
			case code == policy.CodeApprovalAlreadyUsed:
				used.Add(1)
			default:
				t.Errorf("unexpected code %q", code)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || used.Load() != 31 {
		t.Fatalf("wins %d, already used %d", wins.Load(), used.Load())
	}
}

func TestApprovalWebhook(t *testing.T) {
	t.Parallel()
	if _, err := NewApprovalWebhook(WebhookConfig{URL: "ftp://x"}); !errors.Is(err, ErrWebhookURL) {
		t.Fatalf("scheme check = %v", err)
	}
	if _, err := NewApprovalWebhook(WebhookConfig{}); !errors.Is(err, ErrWebhookURL) {
		t.Fatalf("empty URL = %v", err)
	}
	type hit struct {
		body []byte
		sig  string
	}
	hits := make(chan hit, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hits <- hit{b, r.Header.Get("X-TheAuth-Signature")}
	}))
	defer srv.Close()
	secret := []byte("s3cret")
	sink, err := NewApprovalWebhook(WebhookConfig{URL: srv.URL, Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	ap := NewStorageApprovals(memory.New(), WithApprovalEvents(sink), WithApprovalClock(func() time.Time { return now }))
	call := Call{AgentID: "a1", Tool: "pay", Args: map[string]any{"password": "hunter2"}}
	id, _ := ap.Open(context.Background(), call, policy.Escalation{Requirement: policy.RequireApproval})
	_ = ap.Approve(context.Background(), id, "alice") // not in the default Types, must not be sent
	select {
	case h := <-hits:
		m := hmac.New(sha256.New, secret)
		m.Write(h.body)
		if h.sig != "sha256="+hex.EncodeToString(m.Sum(nil)) {
			t.Fatalf("bad signature %q", h.sig)
		}
		s := string(h.body)
		if !strings.Contains(s, `"event":"approval.pending"`) || !strings.Contains(s, id) || strings.Contains(s, "hunter2") {
			t.Fatalf("body = %s", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no webhook delivery")
	}
	select {
	case h := <-hits:
		t.Fatalf("unexpected second delivery: %s", h.body)
	case <-time.After(200 * time.Millisecond):
	}
}
