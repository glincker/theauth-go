package as

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
)

// observability.go folds the span, counter and histogram triple for each token and introspection
// call into one helper. Helpers are nil-safe, so callers never feature-flag instrumentation.

// startTokenSpan opens the theauth.oauth.token span with the grant_type and returns the context,
// span and a latency timer. The histogram is labeled by grant_type only; status lives on the
// counter to keep cardinality bounded.
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

// finishTokenSpan records the outcome on the span and the counter, then ends the span. A non-nil
// err sets StatusError and an error_code derived from *TheAuthError, or "internal" for other
// errors.
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

// startIntrospectSpan opens the theauth.oauth.introspect span. Its histogram is unlabeled.
func (s *Service) startIntrospectSpan(ctx context.Context) (context.Context, obs.Span, obs.Timer) {
	if s == nil {
		return ctx, obs.NoopSpan{}, obs.NewTimer(obs.NoopMetrics{}.Histogram("", nil, nil))
	}
	ctx, span := s.Hooks.StartSpan(ctx, obs.SpanOAuthIntrospect)
	timer := obs.NewTimer(s.mIntrospectLatency)
	return ctx, span, timer
}

// finishIntrospectSpan mirrors finishTokenSpan for introspection. The counter is labeled by status only.
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

// errorCode returns the stable error code for span and metric labels. Non-TheAuth errors map to
// "internal", so dashboards see a bounded enum. err must be non-nil.
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

// observeCacheHit and observeCacheMiss bump the client auth cache counters, labeled by kind. The
// kind is fixed for now.
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

// updateCacheSizeGauge writes the live entry count to the gauge after Put or Invalidate.
func (s *Service) updateCacheSizeGauge() {
	if s == nil || s.mCacheSizeGauge == nil || s.clientAuthCache == nil {
		return
	}
	s.mCacheSizeGauge.Set(float64(s.clientAuthCache.Len()))
}
