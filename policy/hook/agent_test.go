package hook_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/policy/hook"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const agentResource = "https://mcp.example.com"

// recorder is an in process hook that records its input and answers v.
type recorder struct {
	mu    sync.Mutex
	v     hook.Verdict
	calls int
	in    hook.Input
	block bool
}

func (r *recorder) BeforeAuthorize(ctx context.Context, in hook.Input) (hook.Verdict, error) {
	r.mu.Lock()
	r.calls++
	r.in = in
	v, block := r.v, r.block
	r.mu.Unlock()
	if block {
		<-ctx.Done()
		return hook.Verdict{}, ctx.Err()
	}
	return v, nil
}

func newAgentAuth(t *testing.T, runner *hook.Runner) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		EncryptionKey:               bytes.Repeat([]byte{7}, 32),
		Audit:                       &theauth.AuditConfig{FlushInterval: 10 * time.Millisecond},
		SuppressSecureCookieWarning: true, SuppressTrustedProxiesWarning: true,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			Resources:       []theauth.ProtectedResource{{Identifier: agentResource, Scopes: []string{"read"}}},
			DisableRotation: true,
		},
		AgentIdentity: &theauth.AgentConfig{BeforeAuthorize: runner},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, store
}

func newAgent(t *testing.T, a *theauth.TheAuth, store *memory.Store) (theauth.Agent, theauth.User) {
	t.Helper()
	ctx := context.Background()
	u, err := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "owner@example.com", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	ag, _, err := a.CreateAgent(ctx, theauth.CreateAgentInput{Owner: theauth.AgentOwner{UserID: &u.ID}, Name: "bot", Scope: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	return ag, u
}

func TestAuthorizeAgentWithoutHookIsUnchanged(t *testing.T) {
	a, store := newAgentAuth(t, nil)
	ag, _ := newAgent(t, a, store)
	if err := a.AuthorizeAgent(context.Background(), ag.ID.String(), "read", agentResource); err != nil {
		t.Fatalf("default must allow as before, got %v", err)
	}
}

func TestAuthorizeAgentHook(t *testing.T) {
	tests := []struct {
		name     string
		verdict  hook.Verdict
		block    bool
		wantCode hook.Code
	}{
		{name: "allow", verdict: hook.Verdict{Decision: hook.Allow}},
		{name: "deny", verdict: hook.Verdict{Decision: hook.Deny, Reason: "vendor says no", Code: "R7"}, wantCode: hook.CodeHookDenied},
		{name: "escalate", verdict: hook.Verdict{Decision: hook.Escalate}, wantCode: hook.CodeApprovalRequired},
		{name: "timeout", block: true, wantCode: hook.CodeHookTimeout},
		{name: "malformed", verdict: hook.Verdict{Decision: "perhaps"}, wantCode: hook.CodeHookError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{v: tc.verdict, block: tc.block}
			a, store := newAgentAuth(t, &hook.Runner{Hook: rec, Timeout: 50 * time.Millisecond})
			ag, u := newAgent(t, a, store)
			ctx := context.Background()
			if _, err := a.GrantDelegation(ctx, theauth.GrantDelegationInput{
				UserID: u.ID, AgentID: ag.ID, Scope: []string{"read"}, Resource: agentResource, MaxDurationSeconds: 3600,
			}); err != nil {
				t.Fatal(err)
			}
			err := a.AuthorizeAgent(ctx, ag.ID.String(), "read", agentResource)
			if tc.wantCode == "" {
				if err != nil {
					t.Fatalf("got %v", err)
				}
			} else {
				var be *hook.BlockedError
				if !errors.Is(err, theauth.ErrAgentPolicyDenied) || !errors.As(err, &be) || be.Code != tc.wantCode {
					t.Fatalf("got %v, want a policy denial coded %s", err, tc.wantCode)
				}
				waitAudit(t, a, string(tc.wantCode))
			}
			rec.mu.Lock()
			in := rec.in
			rec.mu.Unlock()
			if in.AgentID != ag.ID.String() || in.Action != "read" || in.Resource != agentResource ||
				in.Agent.OwnerID != u.ID.String() || in.Agent.Name != "bot" || in.Delegation.RootOwnerID != u.ID.String() ||
				len(in.Delegation.Path) != 1 || len(in.Delegation.Inbound) != 1 ||
				in.Delegation.Inbound[0].FromAgent != "user:"+u.ID.String() || in.Delegation.Inbound[0].Permissions[0].Actions[0] != "read" {
				t.Fatalf("hook input %+v", in)
			}
		})
	}
}

func TestAuthorizeAgentHookSkipsUnknownAndInactiveAgents(t *testing.T) {
	rec := &recorder{v: hook.Verdict{Decision: hook.Allow}}
	a, store := newAgentAuth(t, &hook.Runner{Hook: rec})
	ag, _ := newAgent(t, a, store)
	ctx := context.Background()
	if err := a.AuthorizeAgent(ctx, ulid.New().String(), "read", agentResource); !errors.Is(err, theauth.ErrAgentNotFound) {
		t.Fatalf("unknown agent: got %v", err)
	}
	if err := a.AuthorizeAgent(ctx, "not-an-id", "read", agentResource); !errors.Is(err, theauth.ErrAgentNotFound) {
		t.Fatalf("malformed id: got %v", err)
	}
	if err := a.SuspendAgent(ctx, ag.ID, "incident"); err != nil {
		t.Fatal(err)
	}
	if err := a.AuthorizeAgent(ctx, ag.ID.String(), "read", agentResource); !errors.Is(err, theauth.ErrAgentInactive) {
		t.Fatalf("suspended agent: got %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.calls != 0 {
		t.Fatalf("hook ran %d times for agents that cannot act", rec.calls)
	}
}

// waitAudit polls the async audit writer for the hook denial record.
func waitAudit(t *testing.T, a *theauth.TheAuth, code string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		events, _, err := a.QueryAudit(context.Background(), theauth.AuditQuery{Action: "agent.authorize_denied"})
		if err == nil && len(events) == 1 {
			md := events[0].Metadata
			if md["decision_code"] != code || md["hook"] == nil {
				t.Fatalf("audit metadata %v", md)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no agent.authorize_denied audit event: %v %v", events, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
