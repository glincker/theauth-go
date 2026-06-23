package observability_test

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	obs "github.com/glincker/theauth-go/internal/observability"
)

// TestNilHooksDoNothing locks the contract that every public Hooks method
// is safe to call on a nil receiver and returns a no-op instrument. The
// library uses this guarantee to skip nil checks at every emit site.
func TestNilHooksDoNothing(t *testing.T) {
	t.Parallel()
	var h *obs.Hooks
	ctx, span := h.StartSpan(context.Background(), "test.span", obs.StringAttr("k", "v"))
	if ctx == nil {
		t.Fatal("StartSpan on nil hooks returned nil ctx")
	}
	if span == nil {
		t.Fatal("StartSpan on nil hooks returned nil span")
	}
	span.SetAttributes(obs.IntAttr("n", 1))
	span.RecordError(errors.New("boom"))
	span.End()

	c := h.Counter("c", obs.Labels{"k": "v"})
	c.Inc()
	c.Add(2)
	hist := h.Histogram("h", obs.Labels{}, obs.LatencyBuckets)
	hist.Observe(0.123)
	g := h.Gauge("g", obs.Labels{})
	g.Set(5)
	g.Inc()
	g.Dec()
}

// TestEmptyHooksUseNoop confirms that a Hooks value with both fields nil
// uses the no-op backends (same path as a nil *Hooks, exercised through a
// concrete value to make sure both code paths agree).
func TestEmptyHooksUseNoop(t *testing.T) {
	t.Parallel()
	h := &obs.Hooks{}
	_, span := h.StartSpan(context.Background(), "test.span")
	if _, ok := span.(obs.NoopSpan); !ok {
		t.Fatalf("expected NoopSpan from empty hooks, got %T", span)
	}
}

// recordingTracer + recordingMetrics are the in-package test doubles. They
// deliberately avoid importing otel or prometheus so the test binary stays
// dep-free (the whole point of the adapter pattern).
type recordingTracer struct {
	mu    sync.Mutex
	spans []recordedSpan
}

type recordedSpan struct {
	Name   string
	Attrs  []obs.Attr
	Ended  bool
	Errors []error
}

func (r *recordingTracer) Start(ctx context.Context, name string, attrs ...obs.Attr) (context.Context, obs.Span) {
	r.mu.Lock()
	r.spans = append(r.spans, recordedSpan{Name: name, Attrs: append([]obs.Attr(nil), attrs...)})
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

func (s *recordingSpan) SetAttributes(attrs ...obs.Attr) {
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
	mu         sync.Mutex
	counters   map[string]*recordingCounter
	histograms map[string]*recordingHistogram
	gauges     map[string]*recordingGauge
}

func newRecordingMetrics() *recordingMetrics {
	return &recordingMetrics{
		counters:   map[string]*recordingCounter{},
		histograms: map[string]*recordingHistogram{},
		gauges:     map[string]*recordingGauge{},
	}
}

func (m *recordingMetrics) Counter(name string, labels obs.Labels) obs.Counter {
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

func (m *recordingMetrics) Histogram(name string, labels obs.Labels, _ []float64) obs.Histogram {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := keyOf(name, labels)
	h, ok := m.histograms[key]
	if !ok {
		h = &recordingHistogram{}
		m.histograms[key] = h
	}
	return h
}

func (m *recordingMetrics) Gauge(name string, labels obs.Labels) obs.Gauge {
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

func keyOf(name string, labels obs.Labels) string {
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

type recordingHistogram struct {
	mu      sync.Mutex
	samples []float64
}

func (h *recordingHistogram) Observe(v float64) {
	h.mu.Lock()
	h.samples = append(h.samples, v)
	h.mu.Unlock()
}

func (h *recordingHistogram) Samples() []float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]float64, len(h.samples))
	copy(out, h.samples)
	return out
}

type recordingGauge struct {
	mu  sync.Mutex
	val float64
}

func (g *recordingGauge) Set(v float64) { g.mu.Lock(); g.val = v; g.mu.Unlock() }
func (g *recordingGauge) Inc()          { g.mu.Lock(); g.val++; g.mu.Unlock() }
func (g *recordingGauge) Dec()          { g.mu.Lock(); g.val--; g.mu.Unlock() }
func (g *recordingGauge) Value() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.val
}

// TestRecordingAdaptersWired confirms that custom adapters are reachable
// through Hooks and observe library-style call patterns. Mirrors how the
// AS, agent, and rate-limit code call into hooks.
func TestRecordingAdaptersWired(t *testing.T) {
	t.Parallel()
	tr := &recordingTracer{}
	mt := newRecordingMetrics()
	h := &obs.Hooks{Tracer: tr, Metrics: mt}

	ctx, span := h.StartSpan(context.Background(), obs.SpanOAuthToken,
		obs.StringAttr(obs.AttrGrantType, "client_credentials"))
	if ctx == nil || span == nil {
		t.Fatal("expected non-nil ctx and span")
	}
	counter := h.Counter(obs.MetricOAuthTokenRequestsTotal, obs.Labels{
		"grant_type": "client_credentials",
		"status":     string(obs.StatusSuccess),
	})
	timer := obs.NewTimer(h.Histogram(obs.MetricOAuthTokenLatency, obs.Labels{
		"grant_type": "client_credentials",
	}, obs.LatencyBuckets))
	counter.Inc()
	time.Sleep(2 * time.Millisecond)
	span.SetAttributes(obs.StringAttr(obs.AttrStatus, string(obs.StatusSuccess)))
	timer.Stop(span)

	if len(tr.spans) != 1 {
		t.Fatalf("want 1 span, got %d", len(tr.spans))
	}
	got := tr.spans[0]
	if got.Name != obs.SpanOAuthToken {
		t.Errorf("span name: want %s got %s", obs.SpanOAuthToken, got.Name)
	}
	if !got.Ended {
		t.Error("span was not ended")
	}
	if len(got.Attrs) < 2 {
		t.Errorf("want at least 2 attrs, got %d", len(got.Attrs))
	}

	c := mt.counters[keyOf(obs.MetricOAuthTokenRequestsTotal, obs.Labels{
		"grant_type": "client_credentials",
		"status":     string(obs.StatusSuccess),
	})]
	if c == nil || c.Value() != 1 {
		t.Errorf("counter not incremented; got %+v", c)
	}

	hist := mt.histograms[keyOf(obs.MetricOAuthTokenLatency, obs.Labels{
		"grant_type": "client_credentials",
	})]
	samples := hist.Samples()
	if len(samples) != 1 {
		t.Fatalf("want 1 histogram sample, got %d", len(samples))
	}
	if samples[0] <= 0 {
		t.Errorf("histogram sample should be positive seconds, got %f", samples[0])
	}
}

// TestErrAttrNilSafe confirms that ErrAttr on a nil error returns an empty
// attribute rather than panicking. Library call sites in defer paths rely
// on this when the operation succeeded.
func TestErrAttrNilSafe(t *testing.T) {
	t.Parallel()
	a := obs.ErrAttr(nil)
	if a.Key != "error" {
		t.Errorf("want key=error, got %s", a.Key)
	}
	if a.Value != "" {
		t.Errorf("want empty value for nil error, got %v", a.Value)
	}
}

// TestStatusConstants confirms the canonical status strings. Locked because
// dashboards key off these values.
func TestStatusConstants(t *testing.T) {
	t.Parallel()
	if obs.StatusSuccess != "success" || obs.StatusError != "error" {
		t.Fatalf("status constants drifted: success=%q error=%q", obs.StatusSuccess, obs.StatusError)
	}
}

// TestLatencyBucketsAreSortedAscending locks the histogram contract that
// adapters depend on.
func TestLatencyBucketsAreSortedAscending(t *testing.T) {
	t.Parallel()
	for i := 1; i < len(obs.LatencyBuckets); i++ {
		if obs.LatencyBuckets[i] <= obs.LatencyBuckets[i-1] {
			t.Fatalf("buckets must be strictly ascending; failed at index %d", i)
		}
	}
}
