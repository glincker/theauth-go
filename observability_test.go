package theauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
)

// recordingTracer + recordingMetrics are duplicated here (instead of
// pulling from internal/observability) so the test confirms the PUBLIC
// re-exported types work for downstream consumers. A consumer building
// their own adapter only sees the theauth.* types; the internal package
// stays out of reach.
type recordingTracer struct {
	mu    sync.Mutex
	spans []recordedSpan
}

type recordedSpan struct {
	Name   string
	Attrs  []theauth.Attr
	Ended  bool
	Errors []error
}

func (r *recordingTracer) Start(ctx context.Context, name string, attrs ...theauth.Attr) (context.Context, theauth.Span) {
	r.mu.Lock()
	r.spans = append(r.spans, recordedSpan{Name: name, Attrs: append([]theauth.Attr(nil), attrs...)})
	idx := len(r.spans) - 1
	r.mu.Unlock()
	return ctx, &recordingSpan{tracer: r, idx: idx}
}

type recordingSpan struct {
	tracer *recordingTracer
	idx    int
}

func (s *recordingSpan) End() {
	s.tracer.mu.Lock()
	defer s.tracer.mu.Unlock()
	s.tracer.spans[s.idx].Ended = true
}

func (s *recordingSpan) SetAttributes(attrs ...theauth.Attr) {
	s.tracer.mu.Lock()
	defer s.tracer.mu.Unlock()
	s.tracer.spans[s.idx].Attrs = append(s.tracer.spans[s.idx].Attrs, attrs...)
}

func (s *recordingSpan) RecordError(err error) {
	if err == nil {
		return
	}
	s.tracer.mu.Lock()
	defer s.tracer.mu.Unlock()
	s.tracer.spans[s.idx].Errors = append(s.tracer.spans[s.idx].Errors, err)
}

type recordingMetrics struct {
	mu       sync.Mutex
	counters map[string]*recordingCounter
	gauges   map[string]*recordingGauge
}

func newRecordingMetrics() *recordingMetrics {
	return &recordingMetrics{
		counters: map[string]*recordingCounter{},
		gauges:   map[string]*recordingGauge{},
	}
}

func (m *recordingMetrics) Counter(name string, labels theauth.Labels) theauth.Counter {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := keyOf(name, labels)
	c, ok := m.counters[key]
	if !ok {
		c = &recordingCounter{}
		m.counters[key] = c
	}
	return c
}

func (m *recordingMetrics) Histogram(_ string, _ theauth.Labels, _ []float64) theauth.Histogram {
	return noopHistogram{}
}

func (m *recordingMetrics) Gauge(name string, labels theauth.Labels) theauth.Gauge {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := keyOf(name, labels)
	g, ok := m.gauges[key]
	if !ok {
		g = &recordingGauge{}
		m.gauges[key] = g
	}
	return g
}

func keyOf(name string, labels theauth.Labels) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := name
	for _, k := range keys {
		s += "|" + k + "=" + labels[k]
	}
	return s
}

type recordingCounter struct {
	mu  sync.Mutex
	val float64
}

func (c *recordingCounter) Inc()           { c.Add(1) }
func (c *recordingCounter) Add(d float64)  { c.mu.Lock(); c.val += d; c.mu.Unlock() }
func (c *recordingCounter) Value() float64 { c.mu.Lock(); defer c.mu.Unlock(); return c.val }

type noopHistogram struct{}

func (noopHistogram) Observe(_ float64) {}

type recordingGauge struct {
	mu  sync.Mutex
	val float64
}

func (g *recordingGauge) Set(v float64) { g.mu.Lock(); g.val = v; g.mu.Unlock() }
func (g *recordingGauge) Inc()          { g.mu.Lock(); g.val++; g.mu.Unlock() }
func (g *recordingGauge) Dec()          { g.mu.Lock(); g.val--; g.mu.Unlock() }

// TestObservabilityWiringNilSafe locks the contract that constructing
// TheAuth without Observability hooks works exactly as before. No spans,
// no metrics, no panics.
func TestObservabilityWiringNilSafe(t *testing.T) {
	t.Parallel()
	a, err := newObsTestAuth(t, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close()
	if h := a.ObservabilityHooks(); h == nil {
		t.Fatal("ObservabilityHooks() returned nil; expected non-nil no-op bundle")
	}
}

// TestObservabilityRateLimitFires confirms that the rate-limit middleware
// increments the theauth_rate_limit_blocked_total counter via the
// consumer-supplied metrics adapter. Locks the wiring end-to-end: Config
// -> TheAuth -> middleware -> consumer.
func TestObservabilityRateLimitFires(t *testing.T) {
	t.Parallel()
	mt := newRecordingMetrics()
	tr := &recordingTracer{}
	hooks := &theauth.Hooks{Tracer: tr, Metrics: mt}
	a, err := newObsTestAuth(t, hooks)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close()

	// Build a middleware that immediately blocks (perMinute=0 means deny all).
	mw := a.RateLimitByIP(1)
	target := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw(target)

	// First request goes through, subsequent fire-storm trips the limiter
	// at least once.
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "203.0.113.5:1234"
		handler.ServeHTTP(w, r)
	}

	c := mt.counters[keyOf(theauth.MetricRateLimitBlockedTotal, theauth.Labels{theauth.AttrRule: "ip"})]
	if c == nil {
		t.Fatalf("expected rate_limit_blocked counter to exist; got nil. all counters: %v",
			counterKeys(mt))
	}
	if c.Value() == 0 {
		t.Errorf("expected rate_limit_blocked counter > 0 after firestorm; got %f", c.Value())
	}
}

// TestObservabilityNilTracerNoPanic confirms that supplying only Metrics
// (Tracer nil) still works. The library should substitute the no-op tracer
// per-field, not require both fields together.
func TestObservabilityNilTracerNoPanic(t *testing.T) {
	t.Parallel()
	mt := newRecordingMetrics()
	hooks := &theauth.Hooks{Tracer: nil, Metrics: mt}
	a, err := newObsTestAuth(t, hooks)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close()
	mw := a.RateLimitByIP(1)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "198.51.100.7:1234"
		h.ServeHTTP(w, r)
	}
}

// TestCanonicalNamesExported pins the catalog of span / metric / attribute
// names exposed at the public surface. Dashboards key off these strings;
// a rename is a breaking change and MUST update consumers explicitly. If
// this test fails, intentional renames need to be reflected in the
// expected list AND in docs/OBSERVABILITY.md.
func TestCanonicalNamesExported(t *testing.T) {
	t.Parallel()
	if theauth.SpanOAuthToken != "theauth.oauth.token" {
		t.Errorf("span name drift: SpanOAuthToken = %q", theauth.SpanOAuthToken)
	}
	if theauth.SpanOAuthIntrospect != "theauth.oauth.introspect" {
		t.Errorf("span name drift: SpanOAuthIntrospect = %q", theauth.SpanOAuthIntrospect)
	}
	if !strings.HasPrefix(theauth.MetricOAuthTokenRequestsTotal, "theauth_") {
		t.Errorf("metric name must start with theauth_; got %q", theauth.MetricOAuthTokenRequestsTotal)
	}
	if theauth.StatusSuccess != "success" || theauth.StatusError != "error" {
		t.Errorf("status enum drift")
	}
}

func counterKeys(m *recordingMetrics) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.counters))
	for k := range m.counters {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func newObsTestAuth(t *testing.T, hooks *theauth.Hooks) (*theauth.TheAuth, error) {
	t.Helper()
	store := memory.New()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://example.test",
		SigningKey:    priv,
		Observability: hooks,
	})
}

// ---------- error code tests (originally errors_test.go) ----------

func TestTheAuthErrorErrorString(t *testing.T) {
	e := theauth.NewError(theauth.CodeWeakPassword, "min 12 chars", nil)
	if got := e.Error(); got != "theauth: weak_password: min 12 chars" {
		t.Fatalf("got %q", got)
	}
	// No message → just code prefix.
	e2 := theauth.NewError(theauth.CodeRateLimited, "", nil)
	if got := e2.Error(); got != "theauth: rate_limited" {
		t.Fatalf("got %q", got)
	}
}

func TestTheAuthErrorUnwrap(t *testing.T) {
	root := errors.New("db down")
	e := theauth.NewError(theauth.CodeInvalidCredentials, "lookup failed", root)
	if !errors.Is(e, root) {
		t.Fatal("errors.Is should walk through Unwrap")
	}
}

// Two TheAuthErrors with the same Code should be Is-equal even when the
// message and inner cause differ. This is the public contract callers rely on.
func TestTheAuthErrorIsByCode(t *testing.T) {
	a := theauth.NewError(theauth.CodeEmailTaken, "exists", fmt.Errorf("pg unique violation"))
	target := &theauth.TheAuthError{Code: theauth.CodeEmailTaken}
	if !errors.Is(a, target) {
		t.Fatal("expected errors.Is to match by Code")
	}
	other := &theauth.TheAuthError{Code: theauth.CodeWeakPassword}
	if errors.Is(a, other) {
		t.Fatal("different Code should not match")
	}
}

func TestTheAuthErrorAs(t *testing.T) {
	wrapped := fmt.Errorf("call site: %w", theauth.NewError(theauth.CodeWeakPassword, "too short", nil))
	var got *theauth.TheAuthError
	if !errors.As(wrapped, &got) {
		t.Fatal("errors.As should extract *TheAuthError")
	}
	if got.Code != theauth.CodeWeakPassword {
		t.Fatalf("got Code=%q", got.Code)
	}
}

func TestTheAuthErrorNilSafe(t *testing.T) {
	var e *theauth.TheAuthError
	if e.Error() != "" {
		t.Fatal("nil receiver Error() should be empty")
	}
	if e.Unwrap() != nil {
		t.Fatal("nil receiver Unwrap() should be nil")
	}
	if e.Is(errors.New("x")) {
		t.Fatal("nil receiver Is() should be false")
	}
}
