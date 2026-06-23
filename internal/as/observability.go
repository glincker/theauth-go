package as

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go/internal/models"
	obs "github.com/glincker/theauth-go/internal/observability"
)

// observability.go: per-service helpers that fold the standard
// span + counter + histogram triple into one call. Used by token.go,
// token_v34.go, introspect.go, and revoke.go so each grant's emit
// surface stays a single line.
//
// All helpers are nil-safe via Hooks.* and tolerate a nil Service so
// existing callers that short-circuit at the top of an entry point on
// s == nil never have to feature-flag the instrumentation.

// startTokenSpan opens the theauth.oauth.token span with the supplied
// grant_type attribute and returns the new context, span, and a
// pre-bound latency timer. The latency histogram uses grant_type as its
// only label (status is on the counter, NOT the histogram, to keep
// cardinality manageable).
func (s *Service) startTokenSpan(ctx context.Context, grantType string) (context.Context, obs.Span, obs.Timer) {
	if s == nil {
		return ctx, obs.NoopSpan{}, obs.NewTimer(obs.NoopMetrics{}.Histogram("", nil, nil))
	}
	ctx, span := s.Hooks.StartSpan(ctx, obs.SpanOAuthToken,
		obs.StringAttr(obs.AttrGrantType, grantType))
	timer := obs.NewTimer(s.Hooks.Histogram(obs.MetricOAuthTokenLatency,
		obs.Labels{obs.AttrGrantType: grantType}, obs.LatencyBuckets))
	return ctx, span, timer
}

// finishTokenSpan records the outcome on both the span and the counter,
// then ends the span. status is StatusSuccess on a nil err; otherwise
// StatusError, the span receives RecordError + the error_code attribute,
// and the counter increments under (grant_type, status="error").
//
// err is unwrapped to *TheAuthError to derive the stable error_code
// string for dashboards; non-TheAuth errors fall back to "internal".
func (s *Service) finishTokenSpan(span obs.Span, timer obs.Timer, grantType string, err error) {
	if s == nil {
		return
	}
	status := obs.StatusSuccess
	if err != nil {
		status = obs.StatusError
		span.RecordError(err)
		span.SetAttributes(obs.StringAttr(obs.AttrErrorCode, errorCode(err)))
	}
	span.SetAttributes(obs.StringAttr(obs.AttrStatus, string(status)))
	counter := s.Hooks.Counter(obs.MetricOAuthTokenRequestsTotal, obs.Labels{
		obs.AttrGrantType: grantType,
		obs.AttrStatus:    string(status),
	})
	counter.Inc()
	timer.Stop(span)
}

// startIntrospectSpan opens the theauth.oauth.introspect span and
// returns the new context, span, and a pre-bound latency timer.
// Introspection has no grant_type axis; the histogram is unlabeled.
func (s *Service) startIntrospectSpan(ctx context.Context) (context.Context, obs.Span, obs.Timer) {
	if s == nil {
		return ctx, obs.NoopSpan{}, obs.NewTimer(obs.NoopMetrics{}.Histogram("", nil, nil))
	}
	ctx, span := s.Hooks.StartSpan(ctx, obs.SpanOAuthIntrospect)
	timer := obs.NewTimer(s.mIntrospectLatency)
	return ctx, span, timer
}

// finishIntrospectSpan mirrors finishTokenSpan for the introspect path.
// The counter labels are (status) only.
func (s *Service) finishIntrospectSpan(span obs.Span, timer obs.Timer, err error) {
	if s == nil {
		return
	}
	status := obs.StatusSuccess
	if err != nil {
		status = obs.StatusError
		span.RecordError(err)
		span.SetAttributes(obs.StringAttr(obs.AttrErrorCode, errorCode(err)))
	}
	span.SetAttributes(obs.StringAttr(obs.AttrStatus, string(status)))
	counter := s.Hooks.Counter(obs.MetricOAuthIntrospectRequestsTotal, obs.Labels{
		obs.AttrStatus: string(status),
	})
	counter.Inc()
	timer.Stop(span)
}

// errorCode extracts the stable error code string from err for span /
// metric label use. Unwraps to *TheAuthError when possible; falls back
// to "internal" for non-TheAuth errors so dashboards see a bounded
// enum rather than free-form error text. err MUST be non-nil; callers
// gate this with their own status check.
func errorCode(err error) string {
	var tae *models.TheAuthError
	if errors.As(err, &tae) {
		if tae.Code == "" {
			return "internal"
		}
		return tae.Code
	}
	return "internal"
}

// observeCacheHit + observeCacheMiss bump the clientauthcache counters
// per (kind) label. The kind is fixed at "oauth_client" today; the label
// exists so a future per-tenant or per-grant breakdown does not break
// dashboards.
func (s *Service) observeCacheHit(kind string) {
	if s == nil {
		return
	}
	s.Hooks.Counter(obs.MetricClientAuthCacheHits, obs.Labels{obs.AttrKind: kind}).Inc()
}

func (s *Service) observeCacheMiss(kind string) {
	if s == nil {
		return
	}
	s.Hooks.Counter(obs.MetricClientAuthCacheMisses, obs.Labels{obs.AttrKind: kind}).Inc()
}

// updateCacheSizeGauge writes the current cache size to the gauge. Called
// after Put / Invalidate so dashboards reflect the live entry count.
// The gauge is bound at New time to the kind="oauth_client" label set;
// no per-call allocation.
func (s *Service) updateCacheSizeGauge() {
	if s == nil || s.mCacheSizeGauge == nil || s.clientAuthCache == nil {
		return
	}
	s.mCacheSizeGauge.Set(float64(s.clientAuthCache.Len()))
}
