package theauth

// observability.go consolidates the audit log + tracing + metrics
// public surface into a single file. PR I (2026-06-22) merged the
// prior audit.go into observability.go so the repository root has
// fewer files and the README renders above the fold on GitHub.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

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

// ---------- Audit log helpers ----------

// redactedMarker is the literal string that replaces secret-flavored values
// in audit metadata. Exported via SeededSecretKeys for callers wanting to
// build their own redactor on the same key list.
const redactedMarker = "[REDACTED]"

// seededSecretKeys is the case-insensitive key blocklist applied by the
// default redactor at any nesting depth. The list intentionally errs on the
// side of over-redaction: better to mask a harmless field than to leak a
// real secret.
var seededSecretKeys = map[string]struct{}{
	"password":      {},
	"secret":        {},
	"token":         {},
	"code":          {},
	"refresh_token": {},
	"access_token":  {},
}

// SeededSecretKeys returns a copy of the case-insensitive key blocklist
// applied by the default redactor. Callers extending the redactor should
// merge this slice with their own additions.
func SeededSecretKeys() []string {
	out := make([]string, 0, len(seededSecretKeys))
	for k := range seededSecretKeys {
		out = append(out, k)
	}
	return out
}

// DefaultRedactor masks values for keys named password, secret, token, code,
// refresh_token, access_token (case-insensitive) at any nesting depth.
// Nested maps and []any are descended; primitive values are kept as-is.
// Returns the same map (mutated in place) for chaining.
//
// Applied once at emit time. A custom Config.Audit.Redactor receives the
// raw metadata and may strip/rename additional fields.
//
// Perf re-audit 2026-06-21 (item 4): key matching now uses
// strings.EqualFold instead of strings.ToLower(k) per call, avoiding a
// heap allocation per metadata key on the hot emit path.
func DefaultRedactor(metadata map[string]any) map[string]any {
	if metadata == nil {
		return nil
	}
	for k, v := range metadata {
		if isSecretKey(k) {
			metadata[k] = redactedMarker
			continue
		}
		metadata[k] = redactValue(v)
	}
	return metadata
}

// isSecretKey reports whether k matches any entry in seededSecretKeys
// using a case-insensitive comparison. EqualFold avoids the per-call
// ToLower allocation of the previous implementation.
func isSecretKey(k string) bool {
	for candidate := range seededSecretKeys {
		if strings.EqualFold(k, candidate) {
			return true
		}
	}
	return false
}

// redactValue recurses into nested maps and slices, applying the same key
// blocklist at every depth. Scalars are returned unchanged.
func redactValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return DefaultRedactor(x)
	case []any:
		for i, elem := range x {
			x[i] = redactValue(elem)
		}
		return x
	case []map[string]any:
		for i := range x {
			x[i] = DefaultRedactor(x[i])
		}
		return x
	default:
		return v
	}
}

// HashEmailForAudit returns sha256(lowercase(email)) hex-encoded. Used by
// emit sites that want to correlate audit rows by email without storing the
// raw plaintext.
func HashEmailForAudit(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}

// AuditSink streams audit events to an external SIEM or observability
// system. Implementations must be best-effort: a failed Stream call must
// never block writes to the canonical storage layer. Failures increment
// Stats.AuditSinkFailed.
//
// Built-in implementations live under audit/sinks/:
//
//   - audit/sinks/otlp: OTLP/HTTP logs exporter
//   - audit/sinks/splunkhec: Splunk HTTP Event Collector
//   - audit/sinks/webhook: generic CloudEvents 1.0 POST
type AuditSink interface {
	// Stream sends a batch of audit events to the external system.
	// Implementations should apply a reasonable timeout internally.
	// A non-nil error is logged and counted in Stats.AuditSinkFailed;
	// it does not affect storage writes.
	Stream(ctx context.Context, batch []AuditEvent) error

	// Name identifies the sink for logging and metrics labels.
	Name() string
}
