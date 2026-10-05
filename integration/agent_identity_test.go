package integration

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/integration/internal/testutil"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

func TestMintAgentToken(t *testing.T) {
	ctx := context.Background()
	e := newTokenEnv(t, nil)
	alice := e.addUser("alice", "read", "deploy")

	tests := []struct {
		name    string
		in      theauth.MintAgentTokenInput
		wantErr error
	}{
		{"within user abilities", theauth.MintAgentTokenInput{UserID: alice.ID, AgentName: "ci-bot", Abilities: []string{"read"}}, nil},
		{"exceeds user abilities", theauth.MintAgentTokenInput{UserID: alice.ID, AgentName: "ci-bot", Abilities: []string{"admin"}}, theauth.ErrAbilityNotHeld},
		{"root not held", theauth.MintAgentTokenInput{UserID: alice.ID, AgentName: "ci-bot", Abilities: []string{theauth.AbilityRoot}}, theauth.ErrAbilityNotHeld},
		{"lifetime above agent cap", theauth.MintAgentTokenInput{UserID: alice.ID, AgentName: "ci-bot", Abilities: []string{"read"}, TTL: 48 * time.Hour}, theauth.ErrTokenTTLInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, tok, err := e.a.MintAgentToken(ctx, tc.in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tok.Kind != theauth.APITokenKindAgent || tok.AgentName != "ci-bot" || tok.DelegatedBy == nil || *tok.DelegatedBy != alice.ID {
				t.Fatalf("token metadata wrong: %+v", tok)
			}
			if got := tok.ExpiresAt.Sub(tok.CreatedAt); got != time.Hour {
				t.Fatalf("default agent lifetime = %v, want 1h", got)
			}
			p, err := e.a.AuthenticateAPIToken(ctx, raw)
			if err != nil {
				t.Fatal(err)
			}
			chain := p.ActorChain()
			if len(chain) != 2 || chain[0].Kind != theauth.ActorKindUser || chain[0].ID != alice.ID.String() || chain[1].Kind != theauth.ActorKindAgent || chain[1].Name != "ci-bot" {
				t.Fatalf("actor chain = %+v", chain)
			}
		})
	}
}

func TestAgentTokenIntersectionReevaluatedPerRequest(t *testing.T) {
	ctx := context.Background()
	e := newTokenEnv(t, nil)
	alice := e.addUser("alice", "read", "deploy")
	raw, _, err := e.a.MintAgentToken(ctx, theauth.MintAgentTokenInput{UserID: alice.ID, AgentName: "bot", Abilities: []string{"read", "deploy"}})
	if err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name     string
		userHas  []string
		wantRead bool
		wantDep  bool
	}{
		{"both held", []string{"read", "deploy"}, true, true},
		{"deploy demoted", []string{"read"}, true, false},
		{"extra user ability does not widen the agent", []string{"read", "deploy", "billing"}, true, true},
		{"all removed", nil, false, false},
	}
	for _, st := range steps {
		e.setAbilities(alice, st.userHas)
		p, err := e.a.AuthenticateAPIToken(ctx, raw)
		if err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		if p.Has("read") != st.wantRead || p.Has("deploy") != st.wantDep || p.Has("billing") {
			t.Fatalf("%s: abilities = %v", st.name, p.Abilities)
		}
	}
	e.disable(alice.ID)
	if _, err := e.a.AuthenticateAPIToken(ctx, raw); !errors.Is(err, theauth.ErrAPITokenInvalid) {
		t.Fatalf("disabled owner accepted: %v", err)
	}
}

func TestDelegatedAbilities(t *testing.T) {
	e := newTokenEnv(t, nil)
	alice := e.addUser("alice", "read", "deploy")
	got, err := e.a.DelegatedAbilities(context.Background(), alice.ID, []string{"deploy", "admin"})
	if err != nil || len(got) != 1 || got[0] != "deploy" {
		t.Fatalf("got %v err %v", got, err)
	}
}

func TestAgentTokenHTTPAndListing(t *testing.T) {
	e := newTokenEnv(t, nil)
	e.addUser("alice", "read", "deploy")
	cases := []struct {
		name   string
		body   map[string]any
		status int
	}{
		{"agent token", map[string]any{"name": "x", "kind": "agent", "agent_name": "mcp-client", "abilities": []string{"read"}}, 201},
		{"agent without name", map[string]any{"name": "x", "kind": "agent", "abilities": []string{"read"}}, 400},
		{"personal with agent name", map[string]any{"name": "x", "agent_name": "mcp", "abilities": []string{"read"}}, 400},
		{"unknown kind", map[string]any{"name": "x", "kind": "robot", "abilities": []string{"read"}}, 400},
	}
	for _, tc := range cases {
		resp, out := e.do("POST", "/auth/tokens", tc.body, e.cookies["alice"], "")
		if resp.StatusCode != tc.status {
			t.Fatalf("%s: status %d body %v", tc.name, resp.StatusCode, out)
		}
		if tc.status == 201 && (out["kind"] != "agent" || out["agentName"] != "mcp-client" || out["delegatedBy"] != e.users["alice"].ID.String()) {
			t.Fatalf("response lacks agent fields: %v", out)
		}
	}
	_, list := e.do("GET", "/auth/tokens", nil, e.cookies["alice"], "")
	toks, _ := list["tokens"].([]any)
	if len(toks) != 1 {
		t.Fatalf("listing = %v", list)
	}
	first, _ := toks[0].(map[string]any)
	if first["kind"] != "agent" || first["agentName"] != "mcp-client" {
		t.Fatalf("listing hides agent fields: %v", first)
	}
}

type auditCapture struct {
	mu     sync.Mutex
	events []theauth.AuditEvent
}

func (c *auditCapture) Name() string { return "capture" }
func (c *auditCapture) Stream(_ context.Context, b []theauth.AuditEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, b...)
	return nil
}

func TestAgentActionAuditRecordsBothActors(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	cap := &auditCapture{}
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		Audit: &theauth.AuditConfig{FlushInterval: 10 * time.Millisecond, Sinks: []theauth.AuditSink{cap}},
		APITokens: &theauth.APITokensConfig{UserAbilities: func(context.Context, *theauth.User) ([]string, error) {
			return []string{"read"}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	u, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "a@x.test", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	raw, _, err := a.MintAgentToken(ctx, theauth.MintAgentTokenInput{UserID: u.ID, AgentName: "log-reader", Abilities: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.With(a.RequireAbility("read")).Get("/act", func(w http.ResponseWriter, r *http.Request) {
		a.EmitAudit(r.Context(), "tool.called", theauth.TargetRef{Type: "tool", ID: "logs"}, map[string]any{"k": "v"})
	})
	srv := httptest.NewServer(r)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/act", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("call: %v %v", resp, err)
	}
	_ = resp.Body.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cap.mu.Lock()
		for _, ev := range cap.events {
			if ev.Action == "tool.called" {
				defer cap.mu.Unlock()
				if ev.ActorUserID == nil || *ev.ActorUserID != u.ID {
					t.Fatalf("event lacks the human actor: %+v", ev)
				}
				if ev.Metadata["actor_agent"] != "log-reader" || ev.Metadata["delegated_by"] != u.ID.String() || ev.Metadata["k"] != "v" {
					t.Fatalf("event lacks the agent actor: %+v", ev.Metadata)
				}
				return
			}
		}
		cap.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("tool.called audit event never arrived")
}

func TestRevocationTargetMatches(t *testing.T) {
	tgt := theauth.RevocationTarget{UserID: "u1", SessionID: "s1", TokenID: "t1", AgentID: "a1", CredentialID: "c1", DelegationID: "d1"}
	tests := []struct {
		name string
		ev   theauth.RevocationEvent
		want bool
	}{
		{"own session", theauth.RevocationEvent{Kind: theauth.RevocationSession, ID: "s1"}, true},
		{"other session", theauth.RevocationEvent{Kind: theauth.RevocationSession, ID: "s2"}, false},
		{"all sessions of owner", theauth.RevocationEvent{Kind: theauth.RevocationSession, UserID: "u1"}, true},
		{"all sessions of someone else", theauth.RevocationEvent{Kind: theauth.RevocationSession, UserID: "u2"}, false},
		{"own token", theauth.RevocationEvent{Kind: theauth.RevocationAPIToken, ID: "t1", UserID: "u2"}, true},
		{"other token same owner", theauth.RevocationEvent{Kind: theauth.RevocationAPIToken, ID: "t2", UserID: "u1"}, false},
		{"all tokens of owner", theauth.RevocationEvent{Kind: theauth.RevocationAPIToken, UserID: "u1"}, true},
		{"owner disabled", theauth.RevocationEvent{Kind: theauth.RevocationOwner, UserID: "u1"}, true},
		{"other owner disabled", theauth.RevocationEvent{Kind: theauth.RevocationOwner, UserID: "u2"}, false},
		{"agent revoked", theauth.RevocationEvent{Kind: theauth.RevocationAgent, ID: "a1"}, true},
		{"agent credential", theauth.RevocationEvent{Kind: theauth.RevocationAgentCredential, ID: "c1"}, true},
		{"delegation", theauth.RevocationEvent{Kind: theauth.RevocationDelegation, ID: "d1"}, true},
		{"delegation other", theauth.RevocationEvent{Kind: theauth.RevocationDelegation, ID: "d2"}, false},
		{"empty target field never matches empty id", theauth.RevocationEvent{Kind: theauth.RevocationAgent}, false},
		{"unknown kind", theauth.RevocationEvent{Kind: "x", ID: "s1"}, false},
	}
	for _, tc := range tests {
		if got := tgt.Matches(tc.ev); got != tc.want {
			t.Errorf("%s: Matches = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// openStream starts an SSE-style request and returns a channel closed when the
// server ends the response.
func openStream(t *testing.T, url string, hdr func(*http.Request)) <-chan struct{} {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	hdr(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("stream status %d", resp.StatusCode)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = resp.Body.Close() }()
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
		}
	}()
	return done
}

func streamServer(t *testing.T, e *tokenEnv, opts theauth.WatchOptions) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	r.With(e.a.RequireAbility("read"), e.a.WatchRevocationMiddleware(opts)).Get("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("data: hello\n\n"))
		fl.Flush()
		<-r.Context().Done()
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func TestRevokeWhileStreaming(t *testing.T) {
	const bound = 2 * time.Second
	ctx := context.Background()
	tests := []struct {
		name string
		opts theauth.WatchOptions
		// setup returns the request mutator and the revoke action.
		setup func(e *tokenEnv, u theauth.User) (func(*http.Request), func())
	}{
		{
			name: "api token revoke",
			setup: func(e *tokenEnv, u theauth.User) (func(*http.Request), func()) {
				raw, tok, _ := e.a.MintAgentToken(ctx, theauth.MintAgentTokenInput{UserID: u.ID, AgentName: "bot", Abilities: []string{"read"}})
				return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+raw) },
					func() { _ = e.a.RevokeAPIToken(ctx, tok.ID) }
			},
		},
		{
			name: "all owner tokens revoked",
			setup: func(e *tokenEnv, u theauth.User) (func(*http.Request), func()) {
				raw, _, _ := e.a.MintAgentToken(ctx, theauth.MintAgentTokenInput{UserID: u.ID, AgentName: "bot", Abilities: []string{"read"}})
				return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+raw) },
					func() { _, _ = e.a.RevokeOwnerAPITokens(ctx, u.ID) }
			},
		},
		{
			name: "owner disabled",
			setup: func(e *tokenEnv, u theauth.User) (func(*http.Request), func()) {
				raw, _, _ := e.a.MintAgentToken(ctx, theauth.MintAgentTokenInput{UserID: u.ID, AgentName: "bot", Abilities: []string{"read"}})
				return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+raw) },
					func() { e.disable(u.ID); _ = e.a.NotifyOwnerDisabled(ctx, u.ID, "disabled") }
			},
		},
		{
			name: "session revoke",
			setup: func(e *tokenEnv, u theauth.User) (func(*http.Request), func()) {
				c := e.cookies["alice"]
				sess, _, _ := testutil.ValidateSessionForTest(e.a, ctx, c.Value)
				return func(r *http.Request) { r.AddCookie(c) }, func() { _ = e.a.RevokeSession(ctx, sess.ID) }
			},
		},
		{
			name: "poll catches a revoke that skipped the bus",
			opts: theauth.WatchOptions{PollInterval: 25 * time.Millisecond},
			setup: func(e *tokenEnv, u theauth.User) (func(*http.Request), func()) {
				raw, tok, _ := e.a.MintAgentToken(ctx, theauth.MintAgentTokenInput{UserID: u.ID, AgentName: "bot", Abilities: []string{"read"}})
				return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+raw) },
					func() { _ = e.store.RevokeAPIToken(ctx, tok.ID, time.Now()) }
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newTokenEnv(t, nil)
			u := e.addUser("alice", "read")
			hdr, revoke := tc.setup(e, u)
			srv := streamServer(t, e, tc.opts)
			done := openStream(t, srv.URL+"/stream", hdr)
			select {
			case <-done:
				t.Fatal("stream ended before any revoke")
			case <-time.After(100 * time.Millisecond):
			}
			start := time.Now()
			revoke()
			select {
			case <-done:
				t.Logf("stream dropped after %v", time.Since(start))
			case <-time.After(bound):
				t.Fatalf("stream still open %v after revoke", bound)
			}
		})
	}
}

type asyncBus struct {
	mu   sync.Mutex
	subs []func(theauth.RevocationEvent)
	got  []theauth.RevocationEvent
}

func (b *asyncBus) Publish(_ context.Context, ev theauth.RevocationEvent) error {
	b.mu.Lock()
	b.got = append(b.got, ev)
	subs := append([]func(theauth.RevocationEvent){}, b.subs...)
	b.mu.Unlock()
	go func() {
		for _, fn := range subs {
			fn(ev)
		}
	}()
	return nil
}

func (b *asyncBus) Subscribe(fn func(theauth.RevocationEvent)) (func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs = append(b.subs, fn)
	return func() {}, nil
}

func TestCustomRevocationBus(t *testing.T) {
	bus := &asyncBus{}
	store := memory.New()
	a, err := theauth.New(theauth.Config{Storage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute, RevocationBus: bus,
		APITokens: &theauth.APITokensConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	id := ulid.New()
	ctx, cancel := a.WatchRevocation(context.Background(), theauth.RevocationTarget{UserID: id.String()}, theauth.WatchOptions{})
	defer cancel(nil)
	if err := a.NotifyOwnerDisabled(context.Background(), id, "deleted"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), theauth.ErrCredentialRevoked) {
			t.Fatalf("cause = %v", context.Cause(ctx))
		}
	case <-time.After(time.Second):
		t.Fatal("custom bus event did not cancel the watcher")
	}
}

func TestRegisterAgentWithDelegation(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		EncryptionKey: bytes.Repeat([]byte{7}, 32),
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			Resources:       []theauth.ProtectedResource{{Identifier: "https://mcp.example.com", Scopes: []string{"read", "write"}}},
			DisableRotation: true,
		},
		AgentIdentity: &theauth.AgentConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	u, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "o@x.test", CreatedAt: time.Now(), UpdatedAt: time.Now()})

	reg, err := a.RegisterAgent(ctx, theauth.RegisterAgentInput{OwnerID: u.ID, Name: "mcp", Scope: []string{"read"}, Resource: "https://mcp.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if reg.Agent.OwnerUserID == nil || *reg.Agent.OwnerUserID != u.ID || reg.Secret.Secret == "" || reg.Grant == nil || reg.Grant.AgentID != reg.Agent.ID {
		t.Fatalf("registration incomplete: %+v", reg)
	}

	wctx, cancel := a.WatchRevocation(ctx, theauth.RevocationTarget{DelegationID: reg.Grant.ID.String()}, theauth.WatchOptions{})
	defer cancel(nil)
	if err := a.RevokeDelegation(ctx, reg.Grant.ID, "test"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wctx.Done():
	case <-time.After(time.Second):
		t.Fatal("delegation revoke did not reach the watcher")
	}

	actx, acancel := a.WatchRevocation(ctx, theauth.RevocationTarget{AgentID: reg.Agent.ID.String()}, theauth.WatchOptions{})
	defer acancel(nil)
	if err := a.RevokeAgent(ctx, reg.Agent.ID, "test"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-actx.Done():
	case <-time.After(time.Second):
		t.Fatal("agent revoke did not reach the watcher")
	}

	bare, _ := theauth.New(theauth.Config{Storage: memory.New(), BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute})
	defer bare.Close()
	if _, err := bare.RegisterAgent(ctx, theauth.RegisterAgentInput{OwnerID: u.ID, Name: "x"}); !errors.Is(err, theauth.ErrAgentIdentityDisabled) {
		t.Fatalf("err = %v", err)
	}
}
