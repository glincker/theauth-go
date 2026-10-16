package as_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/agentpolicy"
	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/policy"
)

func TestAgentPolicyAllowListWithoutAllowFailsClosed(t *testing.T) {
	// Resolver returns a deny only set; the default AllowList mode refuses to
	// treat that as "everything else passes".
	e := engine(t, agentpolicy.Config{Resolver: func(context.Context, theauth.Agent) ([]policy.Policy, error) {
		return []policy.Policy{pol("deny-only", deny("x", "files.delete"))}, nil
	}})
	a, store, cap := newPolicyInstance(t, theauth.AgentConfig{PolicyEngine: e})
	_, sec := newPolicyAgent(t, a, store, "agent")
	_, err := mint(a, sec, "files.read")
	if !errors.Is(err, agentpolicy.ErrNoAllowStatement) || !errors.Is(err, models.ErrOAuthServerBusy) {
		t.Fatalf("want distinct ErrNoAllowStatement failing closed, got %v", err)
	}
	var ev *theauth.AuditEvent
	for i := 0; i < 200 && ev == nil; i++ {
		time.Sleep(5 * time.Millisecond)
		ev = cap.find("agent.policy_resolver_failed")
	}
	if ev == nil || ev.Metadata["error_class"] != "no_allow_statement" {
		t.Fatalf("audit: %+v", ev)
	}
	// Static config with no allow and no resolver is rejected at New.
	if _, err := agentpolicy.New(agentpolicy.Config{Policies: []policy.Policy{pol("d", deny("x", "*"))}}); !errors.Is(err, agentpolicy.ErrNoAllowStatement) {
		t.Fatalf("New: %v", err)
	}
}

// TestAgentPolicyDenyListCaps proves a deny list only narrows: every cap that
// exists without policy still holds when policy would otherwise pass a scope.
func TestAgentPolicyDenyListCaps(t *testing.T) {
	e := engine(t, agentpolicy.Config{Mode: agentpolicy.DenyList, Policies: []policy.Policy{pol("d", deny("no-delete", "files.delete"))}})

	t.Run("client_credentials is capped by the agent registered scopes", func(t *testing.T) {
		a, store, _ := newPolicyInstance(t, theauth.AgentConfig{PolicyEngine: e})
		_, sec := newScopedPolicyAgent(t, a, store, "ro", []string{"files.read"})
		tok, err := mint(a, sec)
		if err != nil || tok.Scope != "files.read" {
			t.Fatalf("default mint must stay at the ceiling: %q %v", tok.Scope, err)
		}
		if _, err := mint(a, sec, "files.write"); !errors.Is(err, theauth.ErrOAuthInvalidScope) {
			t.Fatalf("scope above the ceiling that policy does not deny: %v", err)
		}
	})

	t.Run("client_credentials is capped by the resource catalog", func(t *testing.T) {
		a, store, _ := newPolicyInstance(t, theauth.AgentConfig{PolicyEngine: e})
		_, sec := newScopedPolicyAgent(t, a, store, "wide", []string{"files.read", "files.write", "files.delete", "files.admin"})
		tok, err := mint(a, sec)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Fields(tok.Scope); !slices.Equal(got, []string{"files.read", "files.write"}) {
			t.Fatalf("catalog and policy caps: %v", got)
		}
	})

	t.Run("token exchange is capped by the delegation grant and the user token", func(t *testing.T) {
		a, store, _ := newPolicyInstance(t, theauth.AgentConfig{PolicyEngine: e})
		ctx := context.Background()
		user := theauth.User{ID: ulid.New(), Email: "u@example.com"}
		_, _ = store.CreateUser(ctx, user)
		ag, sec := newPolicyAgent(t, a, store, "agent")
		if _, err := a.GrantDelegation(ctx, theauth.GrantDelegationInput{
			UserID: user.ID, AgentID: ag.ID, Scope: []string{"files.read"},
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
		tok, err := ex()
		if err != nil || tok.Scope != "files.read" {
			t.Fatalf("default exchange must stay at the grant: %q %v", tok.Scope, err)
		}
		if _, err := ex("files.write"); !errors.Is(err, theauth.ErrOAuthInvalidScope) {
			t.Fatalf("scope above the delegation grant: %v", err)
		}
		if _, err := ex("files.delete"); err == nil {
			t.Fatal("denied scope above the grant must not mint")
		}
	})
}

type resolverMetrics struct {
	mu sync.Mutex
	n  map[string]int
}
type resolverCounter struct {
	m   *resolverMetrics
	key string
}

func (c resolverCounter) Inc()          { c.Add(1) }
func (c resolverCounter) Add(v float64) { c.m.mu.Lock(); c.m.n[c.key] += int(v); c.m.mu.Unlock() }
func (m *resolverMetrics) Counter(name string, l obs.Labels) obs.Counter {
	return resolverCounter{m: m, key: name + "|" + l[obs.AttrGrantType]}
}
func (m *resolverMetrics) Histogram(string, obs.Labels, []float64) obs.Histogram {
	return obs.NoopMetrics{}.Histogram("", nil, nil)
}
func (m *resolverMetrics) Gauge(string, obs.Labels) obs.Gauge {
	return obs.NoopMetrics{}.Gauge("", nil)
}
func (m *resolverMetrics) get(k string) int { m.mu.Lock(); defer m.mu.Unlock(); return m.n[k] }

// TestAgentPolicyResolverOutageIsOAuthMintOnly proves a broken resolver is
// visible (audit and metric), fails only agent token mints, and never reaches
// sessions, human login or API token validation on the same instance.
func TestAgentPolicyResolverOutageIsOAuthMintOnly(t *testing.T) {
	var failing atomic.Bool
	var calls atomic.Int64
	e := engine(t, agentpolicy.Config{Resolver: func(context.Context, theauth.Agent) ([]policy.Policy, error) {
		calls.Add(1)
		if failing.Load() {
			return nil, errors.New("iam down SECRET_DSN_postgres://u:p@h/db")
		}
		return []policy.Policy{pol("p", allow("files.*"))}, nil
	}})
	mt := &resolverMetrics{n: map[string]int{}}
	a, store, cap := newPolicyInstanceMut(t, theauth.AgentConfig{PolicyEngine: e}, func(c *theauth.Config) {
		c.Observability = &theauth.Hooks{Metrics: mt}
		c.SessionTTL = time.Hour
		c.SessionLinks = &theauth.SessionLinksConfig{CredentialChecker: theauth.CredentialCheckerFunc(func(context.Context, string) error { return nil })}
		c.APITokens = &theauth.APITokensConfig{
			Prefix: "tk",
			UserAbilities: func(context.Context, *theauth.User) ([]string, error) {
				return []string{"read"}, nil
			},
		}
	})
	ctx := context.Background()
	user, err := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "human@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	_, sec := newPolicyAgent(t, a, store, "agent")
	if _, err := mint(a, sec, "files.read"); err != nil {
		t.Fatalf("healthy mint: %v", err)
	}
	failing.Store(true)
	before := calls.Load()

	// The OAuth mint fails closed and is visible.
	_, err = mint(a, sec, "files.read")
	if !errors.Is(err, models.ErrOAuthServerBusy) {
		t.Fatalf("want fail closed, got %v", err)
	}
	var ev *theauth.AuditEvent
	for i := 0; i < 200 && ev == nil; i++ {
		time.Sleep(5 * time.Millisecond)
		ev = cap.find("agent.policy_resolver_failed")
	}
	if ev == nil {
		t.Fatal("no agent.policy_resolver_failed audit event")
	}
	if ev.Metadata["grant"] != models.AgentMintClientCredentials || ev.Metadata["error_class"] != "resolver_error" || ev.Metadata["client_id"] != sec.ClientID {
		t.Fatalf("audit metadata: %v", ev.Metadata)
	}
	if strings.Contains(strings.ToLower(strings.Join(mapStrings(ev.Metadata), " ")), "secret") {
		t.Fatalf("audit leaks the raw error: %v", ev.Metadata)
	}
	if got := mt.get(theauth.MetricAgentPolicyResolverErrors + "|" + models.AgentMintClientCredentials); got != 1 {
		t.Fatalf("metric %s = %d", theauth.MetricAgentPolicyResolverErrors, got)
	}
	callsAfterMint := calls.Load()
	if callsAfterMint != before+1 {
		t.Fatalf("one mint should call the resolver once: %d -> %d", before, callsAfterMint)
	}

	// Human login (session link exchange), session validation and API tokens
	// keep working and never call the resolver.
	link, _, err := a.MintSessionLink(ctx, theauth.MintSessionLinkInput{UserID: user.ID})
	if err != nil {
		t.Fatalf("MintSessionLink: %v", err)
	}
	cookieTok, sess, err := a.ConsumeSessionLink(ctx, link, "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("session login during outage: %v", err)
	}
	var seen atomic.Bool
	h := a.Authn()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := theauth.UserFromContext(r.Context()); ok && u.ID == user.ID {
			seen.Store(true)
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "theauth_session", Value: cookieTok})
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !seen.Load() || sess.UserID != user.ID {
		t.Fatal("session validation failed during resolver outage")
	}
	raw, _, err := a.MintAPIToken(ctx, theauth.MintAPITokenInput{OwnerID: user.ID, OwnerKind: theauth.OwnerKindUser, Name: "t", Abilities: []string{"read"}})
	if err != nil {
		t.Fatalf("MintAPIToken: %v", err)
	}
	if _, err := a.AuthenticateAPIToken(ctx, raw); err != nil {
		t.Fatalf("API token validation failed during resolver outage: %v", err)
	}
	if calls.Load() != callsAfterMint {
		t.Fatalf("non-OAuth paths called the resolver: %d -> %d", callsAfterMint, calls.Load())
	}

	// Recovery needs no restart.
	failing.Store(false)
	if _, err := mint(a, sec, "files.read"); err != nil {
		t.Fatalf("mint after recovery: %v", err)
	}
}

func mapStrings(m map[string]any) []string {
	var out []string
	for k, v := range m {
		out = append(out, k)
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestAgentPolicyResolverV2PerAgentBudgets(t *testing.T) {
	limits := map[string]*theauth.AgentRateLimit{
		"assistant":  {Requests: 4, Per: time.Hour},
		"mcp-client": {Requests: 2, Per: time.Hour},
		// "auto-fix" has no override and falls back to the config wide budget.
	}
	var mu sync.Mutex
	e := engine(t, agentpolicy.Config{
		ResolverV2: func(_ context.Context, ag theauth.Agent) (agentpolicy.Resolution, error) {
			mu.Lock()
			defer mu.Unlock()
			return agentpolicy.Resolution{Policies: []policy.Policy{pol("p", allow("files.*"))}, RateLimit: limits[ag.Name]}, nil
		},
	})
	a, store, _ := newPolicyInstance(t, theauth.AgentConfig{PolicyEngine: e, RateLimit: theauth.AgentRateLimit{Requests: 1, Per: time.Hour}})
	_, assistant := newPolicyAgent(t, a, store, "assistant")
	_, mcpc := newPolicyAgent(t, a, store, "mcp-client")
	_, autofix := newPolicyAgent(t, a, store, "auto-fix")
	granted := func(sec theauth.AgentSecret, tries int) int {
		n := 0
		for i := 0; i < tries; i++ {
			_, err := mint(a, sec, "files.read")
			switch {
			case err == nil:
				n++
			case errors.Is(err, models.ErrOAuthServerBusy):
				i--
				time.Sleep(20 * time.Millisecond)
			}
		}
		return n
	}
	if n := granted(assistant, 8); n != 4 {
		t.Fatalf("assistant granted %d, want 4", n)
	}
	if n := granted(mcpc, 8); n != 2 {
		t.Fatalf("mcp-client granted %d, want 2", n)
	}
	if n := granted(autofix, 8); n != 1 {
		t.Fatalf("auto-fix granted %d, want 1", n)
	}
	// Raising a limit takes effect on the next request.
	mu.Lock()
	limits["mcp-client"] = &theauth.AgentRateLimit{Requests: 6, Per: time.Hour}
	mu.Unlock()
	if n := granted(mcpc, 10); n != 6 {
		t.Fatalf("mcp-client after raise granted %d, want 6", n)
	}
	// An invalid per agent limit fails closed.
	mu.Lock()
	limits["auto-fix"] = &theauth.AgentRateLimit{Requests: -3}
	mu.Unlock()
	_, err := mint(a, autofix, "files.read")
	if !errors.Is(err, agentpolicy.ErrInvalidRateLimit) || !errors.Is(err, models.ErrOAuthServerBusy) {
		t.Fatalf("invalid limit must fail closed, got %v", err)
	}
}
