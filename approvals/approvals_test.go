package approvals_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/approvals"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

var t0 = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T, allowSelf bool) (http.Handler, *memory.Store) {
	t.Helper()
	store := memory.New()
	open := func(id, openedBy string, expires time.Time) {
		err := store.OpenToolApproval(context.Background(), theauth.ToolApproval{
			ID: id, AgentID: "agent-1", Action: "execute", Resource: "tool:pay",
			OpenedBy: openedBy, CreatedAt: t0, ExpiresAt: expires,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	open("ok", "requester", t0.Add(time.Hour))
	open("self", "alice", t0.Add(time.Hour))
	open("old", "requester", t0.Add(-time.Minute))
	open("done", "requester", t0.Add(time.Hour))
	if ok, _ := store.ApproveToolApproval(context.Background(), "done", "carol", t0); !ok {
		t.Fatal("seed approve")
	}
	h, err := approvals.New(approvals.Config{
		Store: store, Audit: store, AllowSelfApproval: allowSelf,
		Authenticate: func(r *http.Request) (string, error) {
			if u := r.Header.Get("X-User"); u != "" {
				return u, nil
			}
			return "", errors.New("no user")
		},
		IsAdmin: func(_ context.Context, id string) bool { return id != "eve" },
		Now:     func() time.Time { return t0 },
		Arguments: func(theauth.ToolApproval) map[string]any {
			return map[string]any{"api_key": "sk-1", "to": "bob", "nested": map[string]any{"Password": "x"}}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, store
}

func do(h http.Handler, method, path, user string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if user != "" {
		req.Header.Set("X-User", user)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name, path, user string
		allowSelf        bool
		want             int
	}{
		{"approve happy path", "/approvals/ok/approve", "alice", false, 200},
		{"deny happy path", "/approvals/ok/deny", "alice", false, 200},
		{"self approval forbidden", "/approvals/self/approve", "alice", false, 403},
		{"self approval allowed by option", "/approvals/self/approve", "alice", true, 200},
		{"already decided conflict", "/approvals/done/approve", "alice", false, 409},
		{"expired conflict", "/approvals/old/deny", "alice", false, 409},
		{"non admin forbidden", "/approvals/ok/approve", "eve", false, 403},
		{"unauthenticated", "/approvals/ok/approve", "", false, 401},
		{"unknown id", "/approvals/nope/approve", "alice", false, 404},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := setup(t, tc.allowSelf)
			if got := do(h, "POST", tc.path, tc.user).Code; got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestDoubleDecisionAndAudit(t *testing.T) {
	h, store := setup(t, false)
	if c := do(h, "POST", "/approvals/ok/approve", "alice").Code; c != 200 {
		t.Fatalf("first = %d", c)
	}
	if c := do(h, "POST", "/approvals/ok/deny", "bob").Code; c != 409 {
		t.Fatalf("second = %d, want 409", c)
	}
	evs, _, err := store.QueryAuditEvents(context.Background(), theauth.AuditQuery{})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, e := range evs {
		if e.Action == approvals.ActionApproved && e.TargetID == "ok" && e.ActorID == "alice" && e.SubjectID == "agent-1" {
			n++
		}
	}
	if n != 1 || len(evs) != 1 {
		t.Fatalf("audit rows = %d matching of %d", n, len(evs))
	}
}

func TestListAndRedaction(t *testing.T) {
	h, _ := setup(t, false)
	rec := do(h, "GET", "/approvals?status=pending", "alice")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{"sk-1", `"x"`} {
		if strings.Contains(body, leak) {
			t.Fatalf("secret leaked: %s", body)
		}
	}
	var out struct{ Approvals []approvals.View }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Approvals) != 2 {
		t.Fatalf("pending = %d, want 2 (ok, self)", len(out.Approvals))
	}
	if out.Approvals[0].Arguments["to"] != "bob" {
		t.Fatalf("non-secret arg lost: %v", out.Approvals[0].Arguments)
	}
	if c := do(h, "GET", "/approvals?status=bogus", "alice").Code; c != 400 {
		t.Fatalf("bad status = %d", c)
	}
	if c := do(h, "GET", "/approvals", "").Code; c != 401 {
		t.Fatalf("unauth list = %d", c)
	}
	if c := do(h, "GET", "/approvals", "eve").Code; c != 403 {
		t.Fatalf("non-admin list = %d", c)
	}
}

func TestRedactArguments(t *testing.T) {
	big := map[string]any{"blob": strings.Repeat("a", 5000)}
	in := map[string]any{"Authorization": "Bearer z", "list": []any{map[string]any{"client_secret": "s"}}, "n": 1}
	cases := []struct {
		name  string
		in    map[string]any
		check func(t *testing.T, out map[string]any)
	}{
		{"nil", nil, func(t *testing.T, out map[string]any) {
			if out != nil {
				t.Fatal("want nil")
			}
		}},
		{"secrets masked at depth", in, func(t *testing.T, out map[string]any) {
			b, _ := json.Marshal(out)
			if strings.Contains(string(b), "Bearer z") || strings.Contains(string(b), `"s"`) {
				t.Fatalf("leak: %s", b)
			}
			if in["Authorization"] != "Bearer z" {
				t.Fatal("input mutated")
			}
		}},
		{"truncated to 2KB", big, func(t *testing.T, out map[string]any) {
			b, _ := json.Marshal(out)
			if len(b) > approvals.MaxArgumentBytes+200 || out["_truncated"] == nil {
				t.Fatalf("not truncated: %d bytes", len(b))
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.check(t, approvals.RedactArguments(tc.in)) })
	}
}

func TestNewRequiresConfig(t *testing.T) {
	if _, err := approvals.New(approvals.Config{}); !errors.Is(err, approvals.ErrConfig) {
		t.Fatalf("err = %v", err)
	}
}

func quorumSetup(t *testing.T) (http.Handler, *memory.Store) {
	t.Helper()
	h, store := setup(t, true)
	err := store.OpenToolApproval(context.Background(), theauth.ToolApproval{
		ID: "pair", AgentID: "robot-1", Action: "move", Resource: "robot:arm",
		OpenedBy: "requester", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour), RequiredApprovals: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, store
}

func TestQuorumDecide(t *testing.T) {
	h, store := quorumSetup(t)
	view := func(rec *httptest.ResponseRecorder) approvals.View {
		t.Helper()
		var v approvals.View
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	// AllowSelfApproval is on in this setup, and the requester is still refused.
	if c := do(h, "POST", "/approvals/pair/approve", "requester").Code; c != 403 {
		t.Fatalf("requester = %d, want 403", c)
	}
	rec := do(h, "POST", "/approvals/pair/approve", "alice")
	if v := view(rec); rec.Code != 200 || v.Status != approvals.StatusPending || v.ApprovalsReceived != 1 || v.RequiredApprovals != 2 {
		t.Fatalf("first = %d %+v", rec.Code, v)
	}
	if c := do(h, "POST", "/approvals/pair/approve", "alice").Code; c != 409 {
		t.Fatalf("repeat = %d, want 409", c)
	}
	rec = do(h, "POST", "/approvals/pair/approve", "bob")
	if v := view(rec); rec.Code != 200 || v.Status != approvals.StatusApproved || v.ApprovalsReceived != 2 || len(v.Approvers) != 2 {
		t.Fatalf("second = %d %+v", rec.Code, v)
	}
	if c := do(h, "POST", "/approvals/pair/approve", "carol").Code; c != 409 {
		t.Fatalf("after quorum = %d, want 409", c)
	}
	evs, _, _ := store.QueryAuditEvents(context.Background(), theauth.AuditQuery{})
	var votes int
	for _, e := range evs {
		if e.Action == approvals.ActionApproved && e.TargetID == "pair" {
			votes++
		}
	}
	if votes != 2 {
		t.Fatalf("audit rows for the quorum = %d, want 2", votes)
	}
}

func TestQuorumDenyVetoes(t *testing.T) {
	h, _ := quorumSetup(t)
	if c := do(h, "POST", "/approvals/pair/approve", "alice").Code; c != 200 {
		t.Fatalf("approve = %d", c)
	}
	if c := do(h, "POST", "/approvals/pair/deny", "bob").Code; c != 200 {
		t.Fatalf("deny = %d", c)
	}
	if c := do(h, "POST", "/approvals/pair/approve", "carol").Code; c != 409 {
		t.Fatalf("approve after deny = %d, want 409", c)
	}
}
