package as_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/agentpolicy"
	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const agPolResource = "https://files.example.com/mcp"

type policyAudit struct {
	mu     sync.Mutex
	events []theauth.AuditEvent
}

func (c *policyAudit) Name() string { return "capture" }
func (c *policyAudit) Stream(_ context.Context, b []theauth.AuditEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, b...)
	return nil
}
func (c *policyAudit) find(action string) *theauth.AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.events) - 1; i >= 0; i-- {
		if c.events[i].Action == action {
			e := c.events[i]
			return &e
		}
	}
	return nil
}

func newPolicyInstance(t *testing.T, cfg theauth.AgentConfig) (*theauth.TheAuth, *memory.Store, *policyAudit) {
	t.Helper()
	return newPolicyInstanceMut(t, cfg, nil)
}

func newPolicyInstanceMut(t *testing.T, cfg theauth.AgentConfig, mut func(*theauth.Config)) (*theauth.TheAuth, *memory.Store, *policyAudit) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cap := &policyAudit{}
	full := theauth.Config{
		Storage: store, BaseURL: "https://auth.example.com", EncryptionKey: key,
		Audit: &theauth.AuditConfig{FlushInterval: 5 * time.Millisecond, Sinks: []theauth.AuditSink{cap}},
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			Resources:       []theauth.ProtectedResource{{Identifier: agPolResource, Scopes: []string{"files.read", "files.write", "files.delete"}}},
			DisableRotation: true, RegistrationTokens: []string{"initial-access-token"},
		},
		AgentIdentity: &cfg,
	}
	if mut != nil {
		mut(&full)
	}
	a, err := theauth.New(full)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	return a, store, cap
}

func newPolicyAgent(t *testing.T, a *theauth.TheAuth, store *memory.Store, name string) (theauth.Agent, theauth.AgentSecret) {
	t.Helper()
	return newScopedPolicyAgent(t, a, store, name, []string{"files.read", "files.write", "files.delete"})
}

func newScopedPolicyAgent(t *testing.T, a *theauth.TheAuth, store *memory.Store, name string, scopes []string) (theauth.Agent, theauth.AgentSecret) {
	t.Helper()
	ctx := context.Background()
	u := theauth.User{ID: ulid.New(), Email: name + "@example.com"}
	if _, err := store.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	uid := u.ID
	ag, sec, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid}, Name: name, Scope: scopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ag, sec
}

func mint(a *theauth.TheAuth, sec theauth.AgentSecret, scope ...string) (theauth.TokenResponse, error) {
	return a.ClientCredentialsToken(context.Background(), theauth.TokenRequest{
		GrantType: theauth.GrantTypeClientCredentials, ClientID: sec.ClientID, ClientSecret: sec.Secret,
		Resource: agPolResource, Scope: scope,
	})
}

func pol(id string, st ...policy.Statement) policy.Policy {
	return policy.Policy{Version: policy.Version, ID: id, Statements: st}
}

func allow(actions ...string) policy.Statement {
	return policy.Statement{Effect: policy.Allow, Actions: actions, Resources: []string{"*"}}
}

func deny(id string, actions ...string) policy.Statement {
	return policy.Statement{ID: id, Effect: policy.Deny, Actions: actions, Resources: []string{"*"}}
}

func engine(t *testing.T, cfg agentpolicy.Config) *agentpolicy.Engine {
	t.Helper()
	e, err := agentpolicy.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func claimsOf(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a jwt: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAgentPolicyMint(t *testing.T) {
	denylist := pol("levelrail-autonomy", deny("no-delete", "files.delete"), deny("no-write", "files.write"))
	allowRead := pol("read-only", allow("files.read"))
	tests := []struct {
		name       string
		cfg        func(t *testing.T) theauth.AgentConfig
		scope      []string
		wantScope  string
		wantErr    error
		wantNoLeak []string
	}{
		{
			name:      "no engine unchanged",
			cfg:       func(*testing.T) theauth.AgentConfig { return theauth.AgentConfig{} },
			scope:     []string{"files.write"},
			wantScope: "files.write",
		},
		{
			name: "engine without policies unchanged",
			cfg: func(t *testing.T) theauth.AgentConfig {
				return theauth.AgentConfig{PolicyEngine: engine(t, agentpolicy.Config{})}
			},
			scope:     []string{"files.write"},
			wantScope: "files.write",
		},
		{
			name: "explicit deny blocks mint",
			cfg: func(t *testing.T) theauth.AgentConfig {
				return theauth.AgentConfig{PolicyEngine: engine(t, agentpolicy.Config{Mode: agentpolicy.DenyList, Policies: []policy.Policy{denylist}})}
			},
			scope:      []string{"files.read", "files.delete"},
			wantErr:    theauth.ErrAgentPolicyDenied,
			wantNoLeak: []string{"levelrail-autonomy", "no-delete", "explicit deny"},
		},
		{
			name: "denylist drops denied scopes from a defaulted mint",
			cfg: func(t *testing.T) theauth.AgentConfig {
				return theauth.AgentConfig{PolicyEngine: engine(t, agentpolicy.Config{Mode: agentpolicy.DenyList, Policies: []policy.Policy{denylist}})}
			},
			wantScope: "files.read",
		},
		{
			name: "allow narrows a defaulted mint",
			cfg: func(t *testing.T) theauth.AgentConfig {
				return theauth.AgentConfig{PolicyEngine: engine(t, agentpolicy.Config{Policies: []policy.Policy{allowRead}})}
			},
			wantScope: "files.read",
		},
		{
			name: "explicit scope outside allow is invalid_scope",
			cfg: func(t *testing.T) theauth.AgentConfig {
				return theauth.AgentConfig{PolicyEngine: engine(t, agentpolicy.Config{Policies: []policy.Policy{allowRead}})}
			},
			scope:   []string{"files.write"},
			wantErr: theauth.ErrOAuthInvalidScope,
		},
		{
			name: "deny beats allow",
			cfg: func(t *testing.T) theauth.AgentConfig {
				return theauth.AgentConfig{PolicyEngine: engine(t, agentpolicy.Config{
					Policies: []policy.Policy{pol("all", allow("*")), pol("d", deny("x", "files.delete"))},
				})}
			},
			scope:   []string{"files.delete"},
			wantErr: theauth.ErrAgentPolicyDenied,
		},
		{
			name: "every defaulted scope denied fails",
			cfg: func(t *testing.T) theauth.AgentConfig {
				return theauth.AgentConfig{PolicyEngine: engine(t, agentpolicy.Config{Mode: agentpolicy.DenyList, Policies: []policy.Policy{pol("d", deny("x", "*"))}})}
			},
			wantErr: theauth.ErrAgentPolicyDenied,
		},
		{
			name: "resolver error fails closed",
			cfg: func(t *testing.T) theauth.AgentConfig {
				return theauth.AgentConfig{PolicyEngine: engine(t, agentpolicy.Config{
					Resolver: func(context.Context, theauth.Agent) ([]policy.Policy, error) {
						return nil, errors.New("iam store down")
					},
				})}
			},
			scope:      []string{"files.read"},
			wantErr:    models.ErrOAuthServerBusy,
			wantNoLeak: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, store, _ := newPolicyInstance(t, tc.cfg(t))
			_, sec := newPolicyAgent(t, a, store, "agent")
			tok, err := mint(a, sec, tc.scope...)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want %v, got %v", tc.wantErr, err)
				}
				for _, s := range tc.wantNoLeak {
					if strings.Contains(err.Error(), s) {
						t.Fatalf("error leaks %q: %v", s, err)
					}
				}
				if tc.wantErr == theauth.ErrAgentPolicyDenied && !strings.Contains(err.Error(), "files.") {
					t.Fatalf("error should name the denied action: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tok.Scope != tc.wantScope {
				t.Fatalf("scope: want %q got %q", tc.wantScope, tok.Scope)
			}
		})
	}
}

func TestAgentPolicyClaimsAndAudit(t *testing.T) {
	e := engine(t, agentpolicy.Config{Policies: []policy.Policy{
		pol("levelrail-base", allow("files.*")),
		pol("levelrail-autonomy", deny("no-delete", "files.delete")),
	}})
	a, store, cap := newPolicyInstance(t, theauth.AgentConfig{PolicyEngine: e})
	ag, sec := newPolicyAgent(t, a, store, "agent")
	tok, err := mint(a, sec)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Scope != "files.read files.write" {
		t.Fatalf("scope: %q", tok.Scope)
	}
	ap, ok := claimsOf(t, tok.AccessToken)["agent_policy"].(map[string]any)
	if !ok {
		t.Fatalf("agent_policy claim missing")
	}
	ids, _ := ap["ids"].([]any)
	if len(ids) != 2 || ids[0] != "levelrail-autonomy" || ids[1] != "levelrail-base" {
		t.Fatalf("ids: %v", ids)
	}
	if h, _ := ap["hash"].(string); len(h) != 64 {
		t.Fatalf("hash: %v", ap["hash"])
	}
	// Audit is async.
	var ev *theauth.AuditEvent
	for i := 0; i < 200 && ev == nil; i++ {
		time.Sleep(5 * time.Millisecond)
		ev = cap.find("agent.token_minted")
	}
	if ev == nil {
		t.Fatal("no audit event")
	}
	if _, ok := ev.Metadata["agent_policy"]; !ok {
		t.Fatalf("audit lacks agent_policy: %v", ev.Metadata)
	}
	// A denial is audited with the matching statement.
	if _, err := mint(a, sec, "files.delete"); !errors.Is(err, theauth.ErrAgentPolicyDenied) {
		t.Fatalf("want denied, got %v", err)
	}
	var den *theauth.AuditEvent
	for i := 0; i < 200 && den == nil; i++ {
		time.Sleep(5 * time.Millisecond)
		den = cap.find("agent.token_denied")
	}
	if den == nil || den.Metadata["statement_id"] != "no-delete" || den.Metadata["agent_id"] != ag.ID.String() {
		t.Fatalf("denial audit: %+v", den)
	}
}

func TestAgentPolicyNoClaimWithoutPolicy(t *testing.T) {
	a, store, _ := newPolicyInstance(t, theauth.AgentConfig{PolicyEngine: engine(t, agentpolicy.Config{})})
	_, sec := newPolicyAgent(t, a, store, "agent")
	tok, err := mint(a, sec, "files.read")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := claimsOf(t, tok.AccessToken)["agent_policy"]; ok {
		t.Fatal("claim must be absent when no policy applies")
	}
}

func TestAgentPolicyPerAgentResolver(t *testing.T) {
	var seen sync.Map
	e := engine(t, agentpolicy.Config{Mode: agentpolicy.DenyList, Resolver: func(_ context.Context, ag theauth.Agent) ([]policy.Policy, error) {
		seen.Store(ag.Name, true)
		if ag.Name == "restricted" {
			return []policy.Policy{pol("r", deny("x", "files.write"))}, nil
		}
		return nil, nil
	}})
	a, store, _ := newPolicyInstance(t, theauth.AgentConfig{PolicyEngine: e})
	_, restricted := newPolicyAgent(t, a, store, "restricted")
	_, free := newPolicyAgent(t, a, store, "free")
	if _, err := mint(a, restricted, "files.write"); !errors.Is(err, theauth.ErrAgentPolicyDenied) {
		t.Fatalf("restricted: %v", err)
	}
	if _, err := mint(a, free, "files.write"); err != nil {
		t.Fatalf("free: %v", err)
	}
}

func TestAgentRateLimit(t *testing.T) {
	a, store, _ := newPolicyInstance(t, theauth.AgentConfig{
		RateLimit: theauth.AgentRateLimit{Requests: 2, Per: 300 * time.Millisecond},
	})
	_, one := newPolicyAgent(t, a, store, "one")
	_, two := newPolicyAgent(t, a, store, "two")
	for i := 0; i < 2; i++ {
		if _, err := mint(a, one, "files.read"); err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
	}
	_, err := mint(a, one, "files.read")
	var rl *internalas.RateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter <= 0 {
		t.Fatalf("want RateLimitedError with RetryAfter, got %v", err)
	}
	// Another agent has its own budget.
	if _, err := mint(a, two, "files.read"); err != nil {
		t.Fatalf("isolation: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	if _, err := mint(a, one, "files.read"); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

func TestAgentRateLimitInvalid(t *testing.T) {
	_, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "https://auth.example.com", EncryptionKey: make([]byte, 32),
		AuthorizationServer: &theauth.AuthorizationServerConfig{Issuer: "https://auth.example.com", Resources: []theauth.ProtectedResource{{Identifier: agPolResource, Scopes: []string{"a"}}}},
		AgentIdentity:       &theauth.AgentConfig{RateLimit: theauth.AgentRateLimit{Per: time.Second}},
	})
	if !errors.Is(err, theauth.ErrAgentRateLimit) {
		t.Fatalf("want ErrAgentRateLimit, got %v", err)
	}
}

func TestAgentPolicyConcurrent(t *testing.T) {
	e := engine(t, agentpolicy.Config{Mode: agentpolicy.DenyList, Policies: []policy.Policy{pol("d", deny("x", "files.delete"))}})
	a, store, _ := newPolicyInstance(t, theauth.AgentConfig{PolicyEngine: e, RateLimit: theauth.AgentRateLimit{Requests: 100000, Per: time.Second}})
	ag, sec := newPolicyAgent(t, a, store, "agent")
	const workers, perWorker, maxAttempts = 6, 4, 12
	var decided, shed atomic.Int64
	// verdict classifies one response. A response is acceptable only when it is
	// the exact correct decision or the documented Argon2id shed error.
	check := func(kind string, tok theauth.TokenResponse, err error) (decision bool) {
		switch {
		case err != nil && errors.Is(err, models.ErrOAuthServerBusy):
			return false // documented shed: 503 temporarily_unavailable
		case kind == "default":
			if err != nil {
				t.Errorf("default mint: unexpected error %v", err)
				return true
			}
			if got := strings.Fields(tok.Scope); !slices.Equal(got, []string{"files.read", "files.write"}) {
				t.Errorf("default mint scope %v, want [files.read files.write]", got)
			}
		case kind == "denied":
			if !errors.Is(err, theauth.ErrAgentPolicyDenied) {
				t.Errorf("denied mint: got %v (token %q)", err, tok.Scope)
			}
		}
		if strings.Contains(tok.Scope, "files.delete") {
			t.Errorf("a response carried a denied scope: %q", tok.Scope)
		}
		if tok.AccessToken != "" {
			if sc, _ := claimsOf(t, tok.AccessToken)["scope"].(string); strings.Contains(sc, "files.delete") {
				t.Errorf("token claims carried a denied scope: %q", sc)
			}
		}
		return true
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				kind, scope := "default", []string(nil)
				if (w+j)%2 == 1 {
					kind, scope = "denied", []string{"files.read", "files.delete"}
				}
				for attempt := 0; attempt < maxAttempts; attempt++ {
					tok, err := mint(a, sec, scope...)
					if check(kind, tok, err) {
						decided.Add(1)
						break
					}
					shed.Add(1)
					time.Sleep(time.Duration(10+attempt*10) * time.Millisecond)
				}
				// Call-time decisions are never shed.
				if err := a.AuthorizeAgent(context.Background(), ag.ID.String(), "files.delete", agPolResource); !errors.Is(err, theauth.ErrAgentPolicyDenied) {
					t.Errorf("AuthorizeAgent delete: %v", err)
				}
				if err := a.AuthorizeAgent(context.Background(), ag.ID.String(), "files.read", agPolResource); err != nil {
					t.Errorf("AuthorizeAgent read: %v", err)
				}
			}
		}(w)
	}
	wg.Wait()
	total := int64(workers * perWorker)
	if decided.Load() < total/2 {
		t.Fatalf("only %d of %d requests got a real decision (%d shed); the test would pass vacuously", decided.Load(), total, shed.Load())
	}
	t.Logf("decided=%d shed=%d", decided.Load(), shed.Load())
}

func TestAuthorizeAgent(t *testing.T) {
	e := engine(t, agentpolicy.Config{Policies: []policy.Policy{pol("p", allow("tool:*"), deny("no-wire", "tool:wire_transfer"))}})
	a, store, _ := newPolicyInstance(t, theauth.AgentConfig{PolicyEngine: e})
	ag, _ := newPolicyAgent(t, a, store, "agent")
	ctx := context.Background()
	if err := a.AuthorizeAgent(ctx, ag.ID.String(), "tool:search", "doc/1"); err != nil {
		t.Fatalf("allow: %v", err)
	}
	err := a.AuthorizeAgent(ctx, ag.ID.String(), "tool:wire_transfer", "acct/9")
	var denied *theauth.AgentPolicyDeniedError
	if !errors.Is(err, theauth.ErrAgentPolicyDenied) || !errors.As(err, &denied) || denied.Action != "tool:wire_transfer" {
		t.Fatalf("deny: %v", err)
	}
	if err := a.AuthorizeAgent(ctx, "not-a-ulid", "tool:search", "x"); err == nil {
		t.Fatal("unknown agent must fail closed")
	}
	if err := a.AuthorizeAgent(ctx, ulid.New().String(), "tool:search", "x"); err == nil {
		t.Fatal("missing agent must fail closed")
	}
}

func TestAgentPolicyTokenExchange(t *testing.T) {
	e := engine(t, agentpolicy.Config{Policies: []policy.Policy{pol("p", allow("files.*"), deny("no-write", "files.write"))}})
	a, store, _ := newPolicyInstance(t, theauth.AgentConfig{PolicyEngine: e})
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "u@example.com"}
	_, _ = store.CreateUser(ctx, user)
	ag, sec := newPolicyAgent(t, a, store, "agent")
	if _, err := a.GrantDelegation(ctx, theauth.GrantDelegationInput{
		UserID: user.ID, AgentID: ag.ID, Scope: []string{"files.read", "files.write"},
		Resource: agPolResource, MaxDurationSeconds: 3600,
	}); err != nil {
		t.Fatal(err)
	}
	userAccess := userTokenForDelegation(t, a, user, confidentialClient(t, a))
	ex := func(scope ...string) (theauth.TokenResponse, error) {
		return a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
			ClientID: sec.ClientID, ClientSecret: sec.Secret, SubjectToken: userAccess,
			SubjectTokenType: theauth.TokenTypeAccessToken, Resource: agPolResource, Scope: scope,
		})
	}
	if _, err := ex("files.write"); !errors.Is(err, theauth.ErrAgentPolicyDenied) {
		t.Fatalf("want denied, got %v", err)
	}
	tok, err := ex()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(tok.Scope); !slices.Equal(got, []string{"files.read"}) {
		t.Fatalf("narrowed scope: %v", got)
	}
	if _, ok := claimsOf(t, tok.AccessToken)["agent_policy"]; !ok {
		t.Fatal("exchange token lacks agent_policy claim")
	}
}
