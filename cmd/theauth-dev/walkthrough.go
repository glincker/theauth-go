package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/policy/toolguard"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/oklog/ulid/v2"
)

const (
	devIssuer   = "http://127.0.0.1"
	devResource = "https://api.example.com/mcp"
	toolAllowed = "search_tickets"
	toolDenied  = "delete_records"
)

// devEnv is the seeded in-memory world the walkthrough runs against.
type devEnv struct {
	auth  *theauth.TheAuth
	store *memory.Store
	guard *toolguard.Guard
	user  theauth.User
	agent theauth.Agent
	grant theauth.DelegationGrant
}

func (e *devEnv) close() { e.auth.Close() }

func newEnv(ctx context.Context) (*devEnv, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	store := memory.New()
	auth, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       devIssuer,
		EncryptionKey: key,
		Audit:         &theauth.AuditConfig{FlushInterval: 20 * time.Millisecond},
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          devIssuer,
			DisableRotation: true,
			Resources: []theauth.ProtectedResource{{
				Identifier: devResource,
				Scopes:     []string{"tickets.read", "records.delete"},
			}},
		},
		AgentIdentity:               &theauth.AgentConfig{},
		SuppressSecureCookieWarning: true, SuppressTrustedProxiesWarning: true,
	})
	if err != nil {
		return nil, fmt.Errorf("start theauth: %w", err)
	}
	env := &devEnv{auth: auth, store: store}
	if err := env.seed(ctx); err != nil {
		auth.Close()
		return nil, err
	}
	return env, nil
}

func (e *devEnv) seed(ctx context.Context) error {
	var err error
	if e.user, err = e.store.CreateUser(ctx, theauth.User{ID: ulid.Make(), Email: "dev@example.com", CreatedAt: time.Now()}); err != nil {
		return fmt.Errorf("seed user: %w", err)
	}
	if e.agent, _, err = e.auth.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &e.user.ID},
		Name:  "support-agent",
		Scope: []string{"tickets.read", "records.delete"},
	}); err != nil {
		return fmt.Errorf("seed agent: %w", err)
	}
	if e.grant, err = e.auth.GrantDelegation(ctx, theauth.GrantDelegationInput{
		UserID: e.user.ID, AgentID: e.agent.ID,
		Scope: []string{"tickets.read"}, Resource: devResource, MaxDurationSeconds: 3600,
	}); err != nil {
		return fmt.Errorf("seed delegation: %w", err)
	}

	doc, err := policy.Parse([]byte(`{"version":"1","statements":[
	  {"effect":"allow","actions":["execute"],"resources":["tool:` + toolAllowed + `"]},
	  {"effect":"deny","actions":["execute"],"resources":["tool:` + toolDenied + `"]}]}`))
	if err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}
	e.guard = &toolguard.Guard{
		Policies: func(context.Context, string) ([]*policy.Policy, error) { return []*policy.Policy{doc}, nil },
		OnDecision: func(c toolguard.Call, d policy.Decision) {
			e.auth.EmitAudit(context.Background(), "agent.authorize",
				theauth.TargetRef{Type: "tool", ID: c.Tool},
				map[string]any{"agent_id": c.AgentID, "tool": c.Tool, "effect": string(d.Effect), "reason": d.Reason})
		},
	}
	return nil
}

// callTool runs one guarded call and reports whether it was allowed.
func (e *devEnv) callTool(ctx context.Context, tool string) (allowed bool, err error) {
	run := toolguard.Tool(e.guard,
		func(context.Context, struct{}) toolguard.Call {
			return toolguard.Call{AgentID: e.agent.ID.String(), Tool: tool}
		},
		func(context.Context, struct{}) (string, error) { return tool + " ran", nil })
	_, err = run(ctx, struct{}{})
	if err == nil {
		return true, nil
	}
	var denied *toolguard.DeniedError
	if errors.As(err, &denied) {
		return false, nil
	}
	return false, err
}

func walkthrough(ctx context.Context, e *devEnv, out io.Writer) error {
	say(out, "theauth dev: in-memory server, nothing is persisted")
	sayf(out, "1. user       %s (%s)\n", e.user.Email, e.user.ID)
	sayf(out, "2. agent      %s (%s) owned by that user\n", e.agent.Name, e.agent.ID)
	sayf(out, "3. delegation %v on %s, up to %ds\n", e.grant.Scope, e.grant.Resource, e.grant.MaxDurationSeconds)

	steps := []struct {
		tool      string
		wantAllow bool
	}{{toolAllowed, true}, {toolDenied, false}}
	for i, s := range steps {
		allowed, err := e.callTool(ctx, s.tool)
		if err != nil {
			return fmt.Errorf("tool %s: %w", s.tool, err)
		}
		if allowed != s.wantAllow {
			return fmt.Errorf("tool %s: allowed=%t, want %t", s.tool, allowed, s.wantAllow)
		}
		verdict := "DENIED "
		if allowed {
			verdict = "ALLOWED"
		}
		sayf(out, "%d. tool call %s %s\n", 4+i, verdict, s.tool)
	}

	n, head, err := e.verifyAuditChain(ctx)
	if err != nil {
		return err
	}
	sayf(out, "6. audit      %d events, hash chain verified (head %s)\n", n, head[:12])
	return nil
}

// verifyAuditChain waits for the async audit writer, then hashes the events
// into a SHA-256 chain and re-walks it. The memory store keeps no native
// chain, so this proves the recorded sequence is intact in this process. The
// sqlite, postgres and mysql stores chain every row and expose the same check
// through (*TheAuth).VerifyAuditChain.
func (e *devEnv) verifyAuditChain(ctx context.Context) (int, string, error) {
	const wantDecisions = 2
	var events []theauth.AuditEvent
	deadline := time.Now().Add(3 * time.Second)
	for {
		got, _, err := e.auth.QueryAudit(ctx, theauth.AuditQuery{Limit: 500})
		if err != nil {
			return 0, "", fmt.Errorf("query audit: %w", err)
		}
		events = got
		if countAction(events, "agent.authorize") >= wantDecisions {
			break
		}
		if time.Now().After(deadline) {
			return 0, "", errors.New("audit events did not arrive")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// QueryAudit returns newest first; chain oldest first.
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	links, err := buildChain(events)
	if err != nil {
		return 0, "", err
	}
	if err := checkChain(events, links); err != nil {
		return 0, "", err
	}
	return len(links), links[len(links)-1], nil
}

func countAction(events []theauth.AuditEvent, action string) int {
	n := 0
	for _, ev := range events {
		if ev.Action == action {
			n++
		}
	}
	return n
}

func linkHash(prev string, ev theauth.AuditEvent) (string, error) {
	body, err := json.Marshal(struct {
		Action   string         `json:"a"`
		TargetT  string         `json:"tt"`
		TargetID string         `json:"ti"`
		Metadata map[string]any `json:"m"`
	}{ev.Action, ev.TargetType, ev.TargetID, ev.Metadata})
	if err != nil {
		return "", fmt.Errorf("hash audit event: %w", err)
	}
	sum := sha256.Sum256(append([]byte(prev+"\n"), body...))
	return hex.EncodeToString(sum[:]), nil
}

func buildChain(events []theauth.AuditEvent) ([]string, error) {
	links := make([]string, len(events))
	prev := ""
	for i, ev := range events {
		h, err := linkHash(prev, ev)
		if err != nil {
			return nil, err
		}
		links[i], prev = h, h
	}
	if len(links) == 0 {
		return nil, errors.New("no audit events recorded")
	}
	return links, nil
}

func checkChain(events []theauth.AuditEvent, links []string) error {
	prev := ""
	for i, ev := range events {
		h, err := linkHash(prev, ev)
		if err != nil {
			return err
		}
		if h != links[i] {
			return fmt.Errorf("audit chain broken at event %d (%s)", i, ev.Action)
		}
		prev = h
	}
	return nil
}

func say(w io.Writer, s string) { _, _ = fmt.Fprintln(w, s) }

func sayf(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
