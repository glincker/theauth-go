package observability

import (
	"context"
	"time"
)

// Hooks bundles the consumer-supplied observability adapters. Either field
// MAY be nil; the helper methods below substitute the no-op implementations
// so internal call sites never have to branch.
//
// Consumers construct Hooks once at app start, attach it to
// theauth.Config.Observability, and the library wires the bundle into every
// internal service. The bundle is treated as immutable after New; rotating
// tracers or metrics adapters requires reconstructing TheAuth.
type Hooks struct {
	// Tracer is the span starter. When nil, NoopTracer{} is used.
	Tracer Tracer

	// Metrics is the instrument factory. When nil, NoopMetrics{} is used.
	Metrics Metrics
}

// StartSpan is the nil-safe wrapper around Tracer.Start. Call sites use
// this so they never have to check h or h.Tracer for nil.
//
//	ctx, span := hooks.StartSpan(ctx, "theauth.oauth.token", obs.StringAttr("grant_type", req.GrantType))
//	defer span.End()
func (h *Hooks) StartSpan(ctx context.Context, name string, attrs ...Attr) (context.Context, Span) {
	if h == nil || h.Tracer == nil {
		return NoopTracer{}.Start(ctx, name, attrs...)
	}
	return h.Tracer.Start(ctx, name, attrs...)
}

// Counter is the nil-safe wrapper around Metrics.Counter.
func (h *Hooks) Counter(name string, labels Labels) Counter {
	if h == nil || h.Metrics == nil {
		return NoopMetrics{}.Counter(name, labels)
	}
	return h.Metrics.Counter(name, labels)
}

// Histogram is the nil-safe wrapper around Metrics.Histogram.
func (h *Hooks) Histogram(name string, labels Labels, buckets []float64) Histogram {
	if h == nil || h.Metrics == nil {
		return NoopMetrics{}.Histogram(name, labels, buckets)
	}
	return h.Metrics.Histogram(name, labels, buckets)
}

// Gauge is the nil-safe wrapper around Metrics.Gauge.
func (h *Hooks) Gauge(name string, labels Labels) Gauge {
	if h == nil || h.Metrics == nil {
		return NoopMetrics{}.Gauge(name, labels)
	}
	return h.Metrics.Gauge(name, labels)
}

// LatencyBuckets is the shared histogram bucket layout used by every
// _latency_seconds metric the library emits. Documented in
// docs/OBSERVABILITY.md so consumers can pre-register matching Prometheus
// histograms (the bucket layout must match between the library call site
// and the Prometheus registration for the bucket boundaries to align).
//
// Layout rationale: 1 ms floor catches cache-hit fast paths; 5 s ceiling
// matches the upstream HTTP server timeout most ingress proxies enforce.
// The midpoints are roughly log-uniform.
var LatencyBuckets = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5}

// Status is the canonical span / metric status enum used across every
// instrumented operation in the library. Exposed as a string so adapters
// that prefer string labels (Prometheus) and adapters that prefer enums
// (otel) can both round-trip the same value.
type Status string

const (
	// StatusSuccess marks an operation that returned without error.
	StatusSuccess Status = "success"

	// StatusError marks an operation that returned an error to the caller.
	// The accompanying span SHOULD also receive a RecordError call so the
	// adapter can attach the error text under the standard otel error
	// attribute.
	StatusError Status = "error"
)

// Span / metric name constants. The exhaustive list lives here so the
// catalog is auditable in one diff. Consumers building dashboards / alerts
// can import the matching root re-exports (theauth.SpanOAuthToken, etc.)
// and avoid stringly-typed names in their config.
const (
	// Spans.
	SpanOAuthToken             = "theauth.oauth.token"
	SpanOAuthIntrospect        = "theauth.oauth.introspect"
	SpanOAuthRevoke            = "theauth.oauth.revoke"
	SpanOAuthAuthorize         = "theauth.oauth.authorize"
	SpanOAuthDCRRegister       = "theauth.oauth.dcr.register"
	SpanSessionCreate          = "theauth.session.create"
	SpanSessionRevoke          = "theauth.session.revoke"
	SpanPasswordVerify         = "theauth.password.verify"
	SpanWebauthnRegisterBegin  = "theauth.webauthn.register.begin"
	SpanWebauthnRegisterFinish = "theauth.webauthn.register.finish"
	SpanWebauthnLoginBegin     = "theauth.webauthn.login.begin"
	SpanWebauthnLoginFinish    = "theauth.webauthn.login.finish"
	SpanTOTPVerify             = "theauth.totp.verify"
	SpanSAMLACS                = "theauth.saml.acs"
	SpanSCIMUsersList          = "theauth.scim.users.list"
	SpanSCIMUsersGet           = "theauth.scim.users.get"
	SpanSCIMUsersPost          = "theauth.scim.users.post"
	SpanSCIMUsersPatch         = "theauth.scim.users.patch"
	SpanSCIMUsersDelete        = "theauth.scim.users.delete"
	SpanAgentCreate            = "theauth.agent.create"
	SpanAgentSuspend           = "theauth.agent.suspend"
	SpanAgentRevoke            = "theauth.agent.revoke"
	SpanDelegationGrant        = "theauth.delegation.grant"
	SpanDelegationRevoke       = "theauth.delegation.revoke"

	// Counters.
	MetricOAuthTokenRequestsTotal      = "theauth_oauth_token_requests_total"
	MetricOAuthIntrospectRequestsTotal = "theauth_oauth_introspect_requests_total"
	MetricClientAuthCacheHits          = "theauth_clientauthcache_hits_total"
	MetricClientAuthCacheMisses        = "theauth_clientauthcache_misses_total"
	MetricRateLimitBlockedTotal        = "theauth_rate_limit_blocked_total"
	MetricAuditDroppedTotal            = "theauth_audit_dropped_total"

	// Histograms.
	MetricOAuthTokenLatency      = "theauth_oauth_token_latency_seconds"
	MetricOAuthIntrospectLatency = "theauth_oauth_introspect_latency_seconds"

	// Gauges.
	MetricClientAuthCacheSize        = "theauth_clientauthcache_size"
	MetricAuditQueueDepth            = "theauth_audit_queue_depth"
	MetricSessionActive              = "theauth_session_active"
	MetricWebAuthnChallengesInFlight = "theauth_webauthn_challenges_in_flight"
	MetricSAMLInFlightAuthnReq       = "theauth_saml_in_flight_authnreq"

	// Standard attribute keys reused across spans.
	AttrStatus    = "status"
	AttrGrantType = "grant_type"
	AttrClientID  = "client_id"
	AttrErrorCode = "error_code"
	AttrSubject   = "subject"
	AttrScope     = "scope"
	AttrResource  = "resource"
	AttrTenantID  = "tenant_id"
	AttrRule      = "rule"
	AttrKind      = "kind"
)

// Stop is the typed end-time helper. Records the elapsed time on the
// supplied histogram and ends the span. Used as a one-liner deferred at
// the top of an instrumented function:
//
//	ctx, span := hooks.StartSpan(ctx, obs.SpanOAuthToken)
//	timer := obs.NewTimer(hooks.Histogram(obs.MetricOAuthTokenLatency, labels, obs.LatencyBuckets))
//	defer timer.Stop(span)
type Timer struct {
	start     time.Time
	histogram Histogram
}

// NewTimer captures the current wall-clock and binds it to the histogram
// the caller wants the elapsed duration recorded against.
func NewTimer(h Histogram) Timer {
	return Timer{start: time.Now(), histogram: h}
}

// Stop records the elapsed duration (in seconds) on the histogram and ends
// the supplied span. Passing a nil span ends nothing; passing the NoopSpan
// (from NoopTracer) ends in a no-op without allocation.
func (t Timer) Stop(span Span) {
	if t.histogram != nil {
		t.histogram.Observe(time.Since(t.start).Seconds())
	}
	if span != nil {
		span.End()
	}
}

// Elapsed returns the duration since NewTimer without recording or ending.
// Useful when the caller wants to attach the elapsed value as a span
// attribute before calling Stop.
func (t Timer) Elapsed() time.Duration {
	return time.Since(t.start)
}
