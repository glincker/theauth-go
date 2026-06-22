// Package otelbridge bridges theauth.Tracer to go.opentelemetry.io/otel.
//
// Usage:
//
//	import (
//	    "github.com/glincker/theauth-go"
//	    otelbridge "github.com/glincker/theauth-go/examples/observability-otel"
//	    "go.opentelemetry.io/otel"
//	)
//
//	tracer := otel.Tracer("my-service")
//	hooks := &theauth.Hooks{Tracer: otelbridge.New(tracer)}
//	auth, _ := theauth.New(theauth.Config{
//	    ...
//	    Observability: hooks,
//	})
//
// The bridge is intentionally small (under 100 LOC) so consumers can copy
// it inline if they need a tweaked version. Adding new attribute kinds is
// a switch case in toOtelKeyValue below.
package otelbridge

import (
	"context"

	"github.com/glincker/theauth-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Tracer wraps an otel trace.Tracer in the theauth.Tracer interface.
type Tracer struct {
	t trace.Tracer
}

// New returns a bridge backed by the supplied otel tracer. The tracer
// is typically obtained via otel.Tracer("your-service-name").
func New(t trace.Tracer) *Tracer {
	return &Tracer{t: t}
}

// Start opens a child span on the supplied otel tracer. Attributes are
// converted to otel attribute.KeyValue at start time.
func (t *Tracer) Start(ctx context.Context, name string, attrs ...theauth.Attr) (context.Context, theauth.Span) {
	if t == nil || t.t == nil {
		return ctx, noopSpan{}
	}
	otelAttrs := toOtelKeyValues(attrs)
	ctx, span := t.t.Start(ctx, name, trace.WithAttributes(otelAttrs...))
	return ctx, &bridgeSpan{span: span}
}

// bridgeSpan adapts otel trace.Span to theauth.Span.
type bridgeSpan struct {
	span trace.Span
}

func (s *bridgeSpan) End() {
	if s.span != nil {
		s.span.End()
	}
}

func (s *bridgeSpan) SetAttributes(attrs ...theauth.Attr) {
	if s.span == nil {
		return
	}
	s.span.SetAttributes(toOtelKeyValues(attrs)...)
}

func (s *bridgeSpan) RecordError(err error) {
	if s.span == nil || err == nil {
		return
	}
	s.span.RecordError(err)
	s.span.SetStatus(codes.Error, err.Error())
}

// toOtelKeyValues maps theauth.Attr values into otel attribute.KeyValue.
// The type switch covers the four kinds documented in
// internal/observability/tracer.go. Unknown kinds fall back to the
// stringer interface or fmt.Sprintf via attribute.String.
func toOtelKeyValues(attrs []theauth.Attr) []attribute.KeyValue {
	if len(attrs) == 0 {
		return nil
	}
	out := make([]attribute.KeyValue, 0, len(attrs))
	for _, a := range attrs {
		switch v := a.Value.(type) {
		case string:
			out = append(out, attribute.String(a.Key, v))
		case int64:
			out = append(out, attribute.Int64(a.Key, v))
		case int:
			out = append(out, attribute.Int(a.Key, v))
		case float64:
			out = append(out, attribute.Float64(a.Key, v))
		case bool:
			out = append(out, attribute.Bool(a.Key, v))
		case error:
			if v != nil {
				out = append(out, attribute.String(a.Key, v.Error()))
			}
		default:
			// Fallback for fmt.Stringer / arbitrary types. Stringify so
			// the attribute still lands on the span rather than dropping.
			out = append(out, attribute.String(a.Key, stringify(v)))
		}
	}
	return out
}

func stringify(v any) string {
	type stringer interface{ String() string }
	if s, ok := v.(stringer); ok {
		return s.String()
	}
	return ""
}

type noopSpan struct{}

func (noopSpan) End()                            {}
func (noopSpan) SetAttributes(_ ...theauth.Attr) {}
func (noopSpan) RecordError(_ error)             {}
