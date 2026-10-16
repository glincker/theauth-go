package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

type fakeEngine struct {
	dec PolicyDecision
	err error
}

func (f fakeEngine) Decide(context.Context, models.Agent, []PolicyQuery) (PolicyDecision, error) {
	return f.dec, f.err
}

// byAction answers per action so one engine serves a table.
type byAction struct {
	verdicts map[string]PolicyVerdict
	denyList bool
	err      error
}

func (b byAction) Decide(_ context.Context, _ models.Agent, q []PolicyQuery) (PolicyDecision, error) {
	if b.err != nil {
		return PolicyDecision{}, b.err
	}
	d := PolicyDecision{Applies: true, DenyList: b.denyList, IDs: []string{"p1"}, Hash: "h"}
	for _, qq := range q {
		v, ok := b.verdicts[qq.Action]
		if !ok {
			v = PolicyVerdict{Effect: VerdictNone}
		}
		d.Verdicts = append(d.Verdicts, v)
	}
	return d, nil
}

type fakeStorage struct {
	Storage
	agents map[models.ULID]*models.Agent
}

func (f fakeStorage) AgentByID(_ context.Context, id models.ULID) (*models.Agent, error) {
	if a, ok := f.agents[id]; ok {
		return a, nil
	}
	return nil, models.ErrAgentNotFound
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestGateAuthorizeMint(t *testing.T) {
	ag := models.Agent{ID: ulid.New(), Status: models.AgentStatusActive}
	deny := PolicyVerdict{Effect: VerdictDeny, PolicyID: "p1", StatementID: "s1"}
	allow := PolicyVerdict{Effect: VerdictAllow, PolicyID: "p1"}
	tests := []struct {
		name     string
		eng      PolicyEngine
		req      models.AgentMintRequest
		want     []string
		wantDrop []string
		wantErr  error
	}{
		{"nil engine unchanged", nil, models.AgentMintRequest{Scopes: []string{"a", "b"}}, []string{"a", "b"}, nil, nil},
		{"explicit deny fails", byAction{verdicts: map[string]PolicyVerdict{"a": allow, "b": deny}, denyList: false},
			models.AgentMintRequest{Scopes: []string{"a", "b"}, Explicit: true}, nil, nil, models.ErrAgentPolicyDenied},
		{"defaulted deny dropped", byAction{verdicts: map[string]PolicyVerdict{"a": allow, "b": deny}, denyList: false},
			models.AgentMintRequest{Scopes: []string{"a", "b"}}, []string{"a"}, []string{"b"}, nil},
		{"unmatched with allow policies dropped", byAction{verdicts: map[string]PolicyVerdict{"a": allow}, denyList: false},
			models.AgentMintRequest{Scopes: []string{"a", "c"}}, []string{"a"}, []string{"c"}, nil},
		{"explicit unmatched is invalid_scope", byAction{verdicts: map[string]PolicyVerdict{"a": allow}, denyList: false},
			models.AgentMintRequest{Scopes: []string{"c"}, Explicit: true}, nil, nil, models.ErrOAuthInvalidScope},
		{"deny list keeps unmatched", byAction{verdicts: map[string]PolicyVerdict{"b": deny}, denyList: true},
			models.AgentMintRequest{Scopes: []string{"a", "b"}}, []string{"a"}, []string{"b"}, nil},
		{"escalate refused", byAction{verdicts: map[string]PolicyVerdict{"a": {Effect: VerdictEscalate}}, denyList: false},
			models.AgentMintRequest{Scopes: []string{"a"}, Explicit: true}, nil, nil, models.ErrAgentPolicyDenied},
		{"all dropped fails", byAction{verdicts: map[string]PolicyVerdict{"a": deny}, denyList: false},
			models.AgentMintRequest{Scopes: []string{"a"}}, nil, nil, models.ErrAgentPolicyDenied},
		{"deny list never widens past ceiling (defaulted)", byAction{verdicts: map[string]PolicyVerdict{"b": deny}, denyList: true},
			models.AgentMintRequest{Scopes: []string{"a", "z"}, Ceiling: []string{"a"}}, []string{"a"}, []string{"z"}, nil},
		{"deny list never widens past ceiling (explicit)", byAction{verdicts: map[string]PolicyVerdict{"b": deny}, denyList: true},
			models.AgentMintRequest{Scopes: []string{"z"}, Explicit: true, Ceiling: []string{"a"}}, nil, nil, models.ErrOAuthInvalidScope},
		{"resolver error fails closed", byAction{err: errors.New("boom")},
			models.AgentMintRequest{Scopes: []string{"a"}}, nil, nil, models.ErrOAuthServerBusy},
		{"no policies attached unchanged", fakeEngine{dec: PolicyDecision{Applies: false}},
			models.AgentMintRequest{Scopes: []string{"a"}, Explicit: true}, []string{"a"}, nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := &Gate{engine: tc.eng, audit: nopAudit{}}
			if tc.eng == nil {
				g = NewGate(GateConfig{RateLimit: ratelimit.Window{Requests: 100, Per: time.Minute}})
			}
			res, err := g.AuthorizeMint(context.Background(), ag, tc.req)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want %v got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(res.Scopes, tc.want) || !slices.Equal(res.Dropped, tc.wantDrop) {
				t.Fatalf("scopes %v dropped %v", res.Scopes, res.Dropped)
			}
		})
	}
}

func TestGateRateLimitWindowAndIsolation(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	g := NewGate(GateConfig{RateLimit: ratelimit.Window{Requests: 2, Per: time.Minute}, Now: c.now})
	a, b := models.Agent{ID: ulid.New()}, models.Agent{ID: ulid.New()}
	req := models.AgentMintRequest{Scopes: []string{"s"}}
	for i := 0; i < 2; i++ {
		if _, err := g.AuthorizeMint(context.Background(), a, req); err != nil {
			t.Fatal(err)
		}
	}
	_, err := g.AuthorizeMint(context.Background(), a, req)
	var rl *models.AgentRateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter <= 0 || rl.RetryAfter > time.Minute {
		t.Fatalf("want limited, got %v", err)
	}
	if _, err := g.AuthorizeMint(context.Background(), b, req); err != nil {
		t.Fatalf("other agent must have its own budget: %v", err)
	}
	c.add(rl.RetryAfter + time.Millisecond)
	if _, err := g.AuthorizeMint(context.Background(), a, req); err != nil {
		t.Fatalf("must recover after window: %v", err)
	}
}

func TestGateBurst(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	g := NewGate(GateConfig{RateLimit: ratelimit.Window{Requests: 1, Per: time.Minute, Burst: 3}, Now: c.now})
	for i := 0; i < 3; i++ {
		if err := g.CheckRate(context.Background(), "x"); err != nil {
			t.Fatalf("burst %d: %v", i, err)
		}
	}
	if err := g.CheckRate(context.Background(), "x"); err == nil {
		t.Fatal("burst must be bounded")
	}
}

func TestGateAuthorize(t *testing.T) {
	ag := &models.Agent{ID: ulid.New(), Status: models.AgentStatusActive}
	sus := &models.Agent{ID: ulid.New(), Status: models.AgentStatusSuspended}
	st := fakeStorage{agents: map[models.ULID]*models.Agent{ag.ID: ag, sus.ID: sus}}
	eng := byAction{verdicts: map[string]PolicyVerdict{
		"ok":  {Effect: VerdictAllow},
		"bad": {Effect: VerdictDeny, PolicyID: "p1"},
	}, denyList: false}
	g := NewGate(GateConfig{Storage: st, Engine: eng})
	ctx := context.Background()
	if err := g.Authorize(ctx, ag.ID.String(), "ok", "r"); err != nil {
		t.Fatal(err)
	}
	if err := g.Authorize(ctx, ag.ID.String(), "bad", "r"); !errors.Is(err, models.ErrAgentPolicyDenied) {
		t.Fatalf("deny: %v", err)
	}
	if err := g.Authorize(ctx, ag.ID.String(), "other", "r"); !errors.Is(err, models.ErrAgentPolicyDenied) {
		t.Fatalf("default deny: %v", err)
	}
	for _, id := range []string{sus.ID.String(), ulid.New().String(), "junk"} {
		if err := g.Authorize(ctx, id, "ok", "r"); !errors.Is(err, ErrAgentNotActive) {
			t.Fatalf("%s: %v", id, err)
		}
	}
	var nilGate *Gate
	if err := nilGate.Authorize(ctx, "x", "y", "z"); err != nil {
		t.Fatal("nil gate must permit")
	}
}

func TestGateConcurrentRace(t *testing.T) {
	g := NewGate(GateConfig{RateLimit: ratelimit.Window{Requests: 50, Per: time.Second}, MaxKeys: 8,
		Engine: byAction{verdicts: map[string]PolicyVerdict{"a": {Effect: VerdictAllow}}, denyList: false}})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ag := models.Agent{ID: ulid.New()}
			for j := 0; j < 20; j++ {
				_, _ = g.AuthorizeMint(context.Background(), ag, models.AgentMintRequest{Scopes: []string{"a"}})
				_ = g.CheckRate(context.Background(), fmt.Sprintf("k%d", i%12))
			}
		}(i)
	}
	wg.Wait()
	if n := g.limiter.Len(); n > 8 {
		t.Fatalf("limiter exceeded its bound: %d", n)
	}
}

func TestNewGateNilWhenUnconfigured(t *testing.T) {
	if NewGate(GateConfig{}) != nil {
		t.Fatal("unconfigured gate must be nil so behavior is unchanged")
	}
}

type nopAudit struct{}

func (nopAudit) EmitAudit(context.Context, string, models.TargetRef, map[string]any) {}

type auditRec struct {
	mu     sync.Mutex
	events []map[string]any
	names  []string
}

func (a *auditRec) EmitAudit(_ context.Context, action string, _ models.TargetRef, md map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.names = append(a.names, action)
	a.events = append(a.events, md)
}

type countMetrics struct {
	mu sync.Mutex
	n  map[string]int
}

type ctr struct {
	m   *countMetrics
	key string
}

func (c ctr) Inc()          { c.Add(1) }
func (c ctr) Add(v float64) { c.m.mu.Lock(); c.m.n[c.key] += int(v); c.m.mu.Unlock() }

func (m *countMetrics) Counter(name string, l obs.Labels) obs.Counter {
	return ctr{m: m, key: name + "|" + l[obs.AttrGrantType]}
}
func (m *countMetrics) Histogram(string, obs.Labels, []float64) obs.Histogram {
	return obs.NoopMetrics{}.Histogram("", nil, nil)
}
func (m *countMetrics) Gauge(string, obs.Labels) obs.Gauge { return obs.NoopMetrics{}.Gauge("", nil) }

func TestGateEngineFailureAuditAndMetric(t *testing.T) {
	rec := &auditRec{}
	cm := &countMetrics{n: map[string]int{}}
	secret := "tok_SECRET_123"
	g := NewGate(GateConfig{Audit: rec, Hooks: &obs.Hooks{Metrics: cm},
		Engine: byAction{err: &ClassifiedError{Class: ErrClassNoAllow, Err: fmt.Errorf("leaky %s", secret)}}})
	ag := models.Agent{ID: ulid.New(), ClientID: "agent-c1"}
	_, err := g.AuthorizeMint(context.Background(), ag, models.AgentMintRequest{Grant: models.AgentMintTokenExchange, Scopes: []string{"a"}})
	if !errors.Is(err, models.ErrOAuthServerBusy) {
		t.Fatalf("want fail closed busy, got %v", err)
	}
	if len(rec.events) != 1 || rec.names[0] != "agent.policy_resolver_failed" {
		t.Fatalf("audit: %v", rec.names)
	}
	md := rec.events[0]
	if md["agent_id"] != ag.ID.String() || md["client_id"] != "agent-c1" || md["grant"] != models.AgentMintTokenExchange || md["error_class"] != ErrClassNoAllow {
		t.Fatalf("metadata: %v", md)
	}
	if fmt.Sprint(md) != "" && strings.Contains(fmt.Sprint(md), secret) {
		t.Fatalf("audit leaks raw error text: %v", md)
	}
	if cm.n[obs.MetricAgentPolicyResolverErrors+"|"+models.AgentMintTokenExchange] != 1 {
		t.Fatalf("metric: %v", cm.n)
	}
	// Plain engine errors are classed resolver_error.
	g2 := NewGate(GateConfig{Audit: rec, Engine: byAction{err: errors.New("down")}})
	_, _ = g2.AuthorizeMint(context.Background(), ag, models.AgentMintRequest{Grant: "x", Scopes: []string{"a"}})
	if rec.events[len(rec.events)-1]["error_class"] != ErrClassResolver {
		t.Fatalf("class: %v", rec.events[len(rec.events)-1])
	}
}

// perAgent returns a window per agent name through the decision.
type perAgent struct {
	limits map[models.ULID]*ratelimit.Window
}

func (p perAgent) Decide(_ context.Context, ag models.Agent, q []PolicyQuery) (PolicyDecision, error) {
	d := PolicyDecision{Applies: true, DenyList: true, IDs: []string{"p"}, Hash: "h", RateLimit: p.limits[ag.ID]}
	for range q {
		d.Verdicts = append(d.Verdicts, PolicyVerdict{Effect: VerdictNone})
	}
	return d, nil
}

func TestGatePerAgentLimitsIsolatedAndChangeable(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	assistant, mcp, autofix := models.Agent{ID: ulid.New()}, models.Agent{ID: ulid.New()}, models.Agent{ID: ulid.New()}
	limits := map[models.ULID]*ratelimit.Window{
		assistant.ID: {Requests: 5, Per: time.Minute},
		mcp.ID:       {Requests: 2, Per: time.Minute},
		// autofix has no override: uses the default of 1 per minute.
	}
	g := NewGate(GateConfig{Now: c.now, RateLimit: ratelimit.Window{Requests: 1, Per: time.Minute}, Engine: perAgent{limits}})
	req := models.AgentMintRequest{Scopes: []string{"s"}}
	count := func(ag models.Agent) int {
		n := 0
		for i := 0; i < 20; i++ {
			if _, err := g.AuthorizeMint(context.Background(), ag, req); err == nil {
				n++
			}
		}
		return n
	}
	if a, m, f := count(assistant), count(mcp), count(autofix); a != 5 || m != 2 || f != 1 {
		t.Fatalf("budgets assistant=%d mcp=%d autofix=%d", a, m, f)
	}
	// Raising the limit takes effect on the next request.
	limits[mcp.ID] = &ratelimit.Window{Requests: 10, Per: time.Minute}
	if n := count(mcp); n != 10 {
		t.Fatalf("raised budget: %d", n)
	}
	// A caller that cannot resolve overrides keeps the agent's current bucket.
	if err := g.CheckRate(context.Background(), assistant.ID.String()); err == nil {
		t.Fatal("CheckRate must see the assistant's spent bucket")
	}
}
