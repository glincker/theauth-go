// Package otlp provides an AuditSink that exports audit events to an
// OpenTelemetry collector via the OTLP/HTTP logs endpoint. Each call to
// Stream marshals the batch into an ExportLogsServiceRequest protobuf
// message and POSTs it to <endpoint>/v1/logs with Content-Type
// application/x-protobuf.
//
// The OTLP sink lives in a separate Go module
// (github.com/glincker/theauth-go/audit/sinks/otlp) so that the root
// theauth-go module does not gain a dependency on the OTLP proto
// packages. Import this package in your application when you need OTLP
// log export; all other sink types (Splunk HEC, webhook) are in the
// root module and require no extra dependencies.
//
// Usage:
//
//	sink, err := otlp.New("https://otel-collector.example.com:4318")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	cfg := &theauth.AuditConfig{Sinks: []theauth.AuditSink{sink}}
package otlp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	theauth "github.com/glincker/theauth-go"
	collectorlogsv1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

const defaultTimeout = 5 * time.Second

// Sink is an AuditSink that streams to an OTLP/HTTP logs endpoint.
type Sink struct {
	endpoint string
	client   *http.Client
	redactor func(theauth.AuditEvent) theauth.AuditEvent
}

// Option configures a Sink.
type Option func(*Sink)

// WithHTTPClient replaces the default HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(s *Sink) { s.client = c }
}

// WithTimeout sets the per-request HTTP timeout. Defaults to 5s.
func WithTimeout(d time.Duration) Option {
	return func(s *Sink) { s.client = &http.Client{Timeout: d} }
}

// WithRedactor overrides the per-event PII redactor. When not set the
// events are forwarded as-is (already redacted by the canonical writer).
func WithRedactor(r func(theauth.AuditEvent) theauth.AuditEvent) Option {
	return func(s *Sink) { s.redactor = r }
}

// New constructs an OTLP/HTTP logs sink. endpoint is the base URL of the
// OpenTelemetry collector (e.g. "https://otel.example.com:4318"); the
// sink appends "/v1/logs" automatically.
func New(endpoint string, opts ...Option) (*Sink, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("otlp: endpoint must not be empty")
	}
	s := &Sink{
		endpoint: endpoint,
		client:   &http.Client{Timeout: defaultTimeout},
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Name returns the sink identifier used in logs and metrics.
func (s *Sink) Name() string { return "otlp" }

// Stream marshals the batch into an ExportLogsServiceRequest and POSTs
// it to <endpoint>/v1/logs. Returns an error for any non-2xx response
// or network/marshaling failure.
func (s *Sink) Stream(ctx context.Context, batch []theauth.AuditEvent) error {
	logRecords := make([]*logsv1.LogRecord, 0, len(batch))
	for _, evt := range batch {
		if s.redactor != nil {
			evt = s.redactor(evt)
		}
		lr, err := eventToLogRecord(evt)
		if err != nil {
			return fmt.Errorf("otlp: encode event %s: %w", evt.ID, err)
		}
		logRecords = append(logRecords, lr)
	}

	req := &collectorlogsv1.ExportLogsServiceRequest{
		ResourceLogs: []*logsv1.ResourceLogs{
			{
				Resource: &resourcev1.Resource{
					Attributes: []*commonv1.KeyValue{
						{
							Key:   "service.name",
							Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: "theauth-go"}},
						},
					},
				},
				ScopeLogs: []*logsv1.ScopeLogs{
					{
						LogRecords: logRecords,
					},
				},
			},
		},
	}

	body, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("otlp: proto marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.endpoint+"/v1/logs", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlp: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("otlp: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// eventToLogRecord converts an AuditEvent to an OTLP LogRecord. The full
// event is JSON-encoded into the Body as a string value so OTLP consumers
// can parse the structured payload. Key fields are also promoted to
// Attributes so they are queryable without parsing the body.
func eventToLogRecord(evt theauth.AuditEvent) (*logsv1.LogRecord, error) {
	bodyJSON, err := json.Marshal(evt)
	if err != nil {
		return nil, err
	}
	attrs := []*commonv1.KeyValue{
		strAttr("audit.action", evt.Action),
		strAttr("audit.target_type", evt.TargetType),
		strAttr("audit.target_id", evt.TargetID),
		strAttr("audit.id", evt.ID.String()),
	}
	if evt.OrganizationID != nil {
		attrs = append(attrs, strAttr("audit.organization_id", evt.OrganizationID.String()))
	}
	if evt.ActorUserID != nil {
		attrs = append(attrs, strAttr("audit.actor_user_id", evt.ActorUserID.String()))
	}
	if evt.IP != "" {
		attrs = append(attrs, strAttr("audit.ip", evt.IP))
	}

	return &logsv1.LogRecord{
		TimeUnixNano:         uint64(evt.CreatedAt.UnixNano()),
		ObservedTimeUnixNano: uint64(evt.CreatedAt.UnixNano()),
		SeverityNumber:       logsv1.SeverityNumber_SEVERITY_NUMBER_INFO,
		SeverityText:         "INFO",
		Body: &commonv1.AnyValue{
			Value: &commonv1.AnyValue_StringValue{StringValue: string(bodyJSON)},
		},
		Attributes: attrs,
	}, nil
}

func strAttr(key, value string) *commonv1.KeyValue {
	return &commonv1.KeyValue{
		Key:   key,
		Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: value}},
	}
}
