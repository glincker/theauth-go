package observability

import (
	"context"
)

// Tracer is the minimal span-starter interface adapters implement. Consumers
// wire a concrete Tracer (typically backed by go.opentelemetry.io/otel) via
// theauth.Config.Observability.Tracer; the library calls Start at the
// boundary of every instrumented operation.
//
// Implementations MUST be safe to call from any goroutine. Implementations
// MUST return a non-nil Span; the helpers below (NoopTracer, hooks.StartSpan)
// guarantee this for the no-op path so the library code never has to nil-check
// the returned span.
type Tracer interface {
	// Start opens a new span named name as a child of any span already
	// attached to ctx. The returned context carries the new span so nested
	// Start calls in the same goroutine attach correctly. The returned
	// Span MUST be ended exactly once by the caller (usually via defer
	// span.End()).
	//
	// attrs are evaluated once at span start. Subsequent attributes flow
	// through Span.SetAttributes so consumers honor span sampling decisions
	// without paying for attribute building on dropped spans.
	Start(ctx context.Context, name string, attrs ...Attr) (context.Context, Span)
}

// Span is the per-operation span handle adapters return from Tracer.Start.
// Implementations MUST be safe to call from a single goroutine; the library
// guarantees no concurrent calls on a single Span instance.
type Span interface {
	// End closes the span. Calling End more than once is a programmer
	// error; adapters MAY no-op subsequent calls but MUST NOT panic.
	End()

	// SetAttributes attaches additional attributes to the span after it
	// has started. Adapters apply these before End. Calling SetAttributes
	// after End is a programmer error; adapters MAY drop late attributes
	// silently.
	SetAttributes(attrs ...Attr)

	// RecordError attaches an error to the span. Adapters typically also
	// mark the span as errored (e.g. otel span.SetStatus(codes.Error, ...)).
	// Calling RecordError with a nil error is a no-op.
	RecordError(err error)
}

// Attr is one key/value pair attached to a span. Value may be any of:
// string, int64, float64, bool, error, fmt.Stringer. Adapters that bridge
// to otel are encouraged to type-switch on Value and emit the matching
// otel attribute kind; unknown kinds SHOULD render as fmt.Sprintf("%v", v).
type Attr struct {
	Key   string
	Value any
}

// StringAttr is the canonical helper for string-valued attributes. Library
// call sites use this so the adapter never has to type-switch a bare string.
func StringAttr(k, v string) Attr { return Attr{Key: k, Value: v} }

// IntAttr wraps an int64 attribute. Counts and bounded enums use this.
func IntAttr(k string, v int64) Attr { return Attr{Key: k, Value: v} }

// BoolAttr wraps a bool attribute.
func BoolAttr(k string, v bool) Attr { return Attr{Key: k, Value: v} }

// ErrAttr is shorthand for attaching an error as a string attribute under
// the standard key "error". Adapters may also call Span.RecordError; this
// helper is the cheap path for adding the error text without building a
// full Status object.
func ErrAttr(err error) Attr {
	if err == nil {
		return Attr{Key: "error", Value: ""}
	}
	return Attr{Key: "error", Value: err.Error()}
}

// NoopTracer is the default Tracer used when Hooks.Tracer is nil. Every
// span it returns is a NoopSpan whose methods drop the call. The library
// uses NoopTracer{} unconditionally when no consumer-supplied tracer is
// wired so call sites never have to nil-check.
type NoopTracer struct{}

// Start on NoopTracer returns the supplied context unchanged plus a
// NoopSpan instance.
func (NoopTracer) Start(ctx context.Context, _ string, _ ...Attr) (context.Context, Span) {
	return ctx, NoopSpan{}
}

// NoopSpan is the Span returned by NoopTracer. All methods are no-ops.
type NoopSpan struct{}

// End on NoopSpan is a no-op.
func (NoopSpan) End() {}

// SetAttributes on NoopSpan is a no-op.
func (NoopSpan) SetAttributes(_ ...Attr) {}

// RecordError on NoopSpan is a no-op.
func (NoopSpan) RecordError(_ error) {}
