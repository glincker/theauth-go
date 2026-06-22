package theauth

import (
	"github.com/glincker/theauth-go/internal/observability"
)

// Observability re-exports are the public surface for plugging tracing +
// metrics adapters into TheAuth. The underlying types live in
// internal/observability so the implementation is auditable in one diff
// and downstream consumers never import an internal/ path.
//
// Design (locked 2026-06-21):
//
//   - Adapter pattern, NO hard dependency on OpenTelemetry, Prometheus, or
//     any other vendor. Consumers wire their own implementations.
//   - mcpresource/go.mod stays zero-dep; it never depends on this package.
//   - Cardinality discipline: high-cardinality identifiers (client_id,
//     user_id, IP) go on spans as attributes, NEVER on metric labels.
//
// See examples/observability-otel and examples/observability-prom for
// reference adapter implementations.

// Tracer is the span starter adapters implement. See
// internal/observability.Tracer for the full contract.
type Tracer = observability.Tracer

// Span is the per-operation span handle.
type Span = observability.Span

// Attr is one key/value pair attached to a span.
type Attr = observability.Attr

// StringAttr wraps a string-valued span attribute.
func StringAttr(k, v string) Attr { return observability.StringAttr(k, v) }

// IntAttr wraps an int64 span attribute.
func IntAttr(k string, v int64) Attr { return observability.IntAttr(k, v) }

// BoolAttr wraps a bool span attribute.
func BoolAttr(k string, v bool) Attr { return observability.BoolAttr(k, v) }

// ErrAttr wraps an error as a string span attribute under the key "error".
func ErrAttr(err error) Attr { return observability.ErrAttr(err) }

// Metrics is the instrument factory adapters implement. See
// internal/observability.Metrics for the full contract.
type Metrics = observability.Metrics

// Counter is a monotonic counter.
type Counter = observability.Counter

// Histogram is a distribution histogram.
type Histogram = observability.Histogram

// Gauge is a settable, incrementable, decrementable instantaneous value.
type Gauge = observability.Gauge

// Labels is the (name -> value) label set for a single metric instance.
// Cardinality discipline: callers MUST NOT put high-cardinality identifiers
// into Labels.
type Labels = observability.Labels

// Hooks bundles the consumer-supplied observability adapters. Attach to
// Config.Observability to wire tracing + metrics into TheAuth. Either
// field MAY be nil; the library falls back to no-op adapters per field.
type Hooks = observability.Hooks

// Status is the canonical span / metric status enum used across every
// instrumented operation in the library.
type Status = observability.Status

// Span / metric / attribute names re-exported so consumers building
// dashboards or alerts can reference them by symbol rather than by
// stringly-typed name.
const (
	StatusSuccess = observability.StatusSuccess
	StatusError   = observability.StatusError

	SpanOAuthToken             = observability.SpanOAuthToken
	SpanOAuthIntrospect        = observability.SpanOAuthIntrospect
	SpanOAuthRevoke            = observability.SpanOAuthRevoke
	SpanOAuthAuthorize         = observability.SpanOAuthAuthorize
	SpanOAuthDCRRegister       = observability.SpanOAuthDCRRegister
	SpanSessionCreate          = observability.SpanSessionCreate
	SpanSessionRevoke          = observability.SpanSessionRevoke
	SpanPasswordVerify         = observability.SpanPasswordVerify
	SpanWebauthnRegisterBegin  = observability.SpanWebauthnRegisterBegin
	SpanWebauthnRegisterFinish = observability.SpanWebauthnRegisterFinish
	SpanWebauthnLoginBegin     = observability.SpanWebauthnLoginBegin
	SpanWebauthnLoginFinish    = observability.SpanWebauthnLoginFinish
	SpanTOTPVerify             = observability.SpanTOTPVerify
	SpanSAMLACS                = observability.SpanSAMLACS
	SpanSCIMUsersList          = observability.SpanSCIMUsersList
	SpanSCIMUsersGet           = observability.SpanSCIMUsersGet
	SpanSCIMUsersPost          = observability.SpanSCIMUsersPost
	SpanSCIMUsersPatch         = observability.SpanSCIMUsersPatch
	SpanSCIMUsersDelete        = observability.SpanSCIMUsersDelete
	SpanAgentCreate            = observability.SpanAgentCreate
	SpanAgentSuspend           = observability.SpanAgentSuspend
	SpanAgentRevoke            = observability.SpanAgentRevoke
	SpanDelegationGrant        = observability.SpanDelegationGrant
	SpanDelegationRevoke       = observability.SpanDelegationRevoke

	MetricOAuthTokenRequestsTotal      = observability.MetricOAuthTokenRequestsTotal
	MetricOAuthTokenLatency            = observability.MetricOAuthTokenLatency
	MetricOAuthIntrospectRequestsTotal = observability.MetricOAuthIntrospectRequestsTotal
	MetricOAuthIntrospectLatency       = observability.MetricOAuthIntrospectLatency
	MetricClientAuthCacheHits          = observability.MetricClientAuthCacheHits
	MetricClientAuthCacheMisses        = observability.MetricClientAuthCacheMisses
	MetricClientAuthCacheSize          = observability.MetricClientAuthCacheSize
	MetricRateLimitBlockedTotal        = observability.MetricRateLimitBlockedTotal
	MetricAuditDroppedTotal            = observability.MetricAuditDroppedTotal
	MetricAuditQueueDepth              = observability.MetricAuditQueueDepth
	MetricSessionActive                = observability.MetricSessionActive
	MetricWebAuthnChallengesInFlight   = observability.MetricWebAuthnChallengesInFlight
	MetricSAMLInFlightAuthnReq         = observability.MetricSAMLInFlightAuthnReq

	AttrStatus    = observability.AttrStatus
	AttrGrantType = observability.AttrGrantType
	AttrClientID  = observability.AttrClientID
	AttrErrorCode = observability.AttrErrorCode
	AttrSubject   = observability.AttrSubject
	AttrScope     = observability.AttrScope
	AttrResource  = observability.AttrResource
	AttrTenantID  = observability.AttrTenantID
	AttrRule      = observability.AttrRule
	AttrKind      = observability.AttrKind
)

// LatencyBuckets is the shared histogram bucket layout used by every
// _latency_seconds metric the library emits. Consumers pre-registering
// Prometheus histograms MUST use this exact slice so bucket boundaries
// align between library call sites and consumer registrations.
var LatencyBuckets = observability.LatencyBuckets

// coalesceHooks returns a non-nil *Hooks. The constructor uses this so
// every internal service can call hooks.StartSpan / hooks.Counter without
// nil-checking the pointer (the nil-safe helpers handle nil inner fields).
func coalesceHooks(h *Hooks) *Hooks {
	if h == nil {
		return &Hooks{}
	}
	return h
}

// Hooks returns the observability bundle in use. Returns a non-nil pointer
// even when no Observability was configured (the no-op bundle). Exposed so
// consumers writing custom services on top of theauth-go can share the
// same Tracer / Metrics adapters without re-wiring.
func (a *TheAuth) ObservabilityHooks() *Hooks {
	if a == nil {
		return &Hooks{}
	}
	return a.hooks
}
