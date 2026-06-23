// Package splunkhec provides an AuditSink that forwards batches of audit
// events to a Splunk HTTP Event Collector (HEC) endpoint. Each event is
// wrapped in a Splunk HEC envelope and POSTed as a JSON newline-delimited
// body to POST /services/collector/event.
//
// Usage:
//
//	sink, err := splunkhec.New("https://splunk.example.com:8088", "my-hec-token")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	cfg := &theauth.AuditConfig{Sinks: []theauth.AuditSink{sink}}
package splunkhec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/internal/models"
)

const defaultTimeout = 5 * time.Second

// hecEvent is the Splunk HEC envelope for a single event.
type hecEvent struct {
	Event      models.AuditEvent `json:"event"`
	Source     string            `json:"source"`
	Sourcetype string            `json:"sourcetype"`
}

// Sink is an AuditSink that streams to Splunk HEC.
type Sink struct {
	endpoint string
	token    string
	client   *http.Client
	redactor func(models.AuditEvent) models.AuditEvent
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
func WithRedactor(r func(models.AuditEvent) models.AuditEvent) Option {
	return func(s *Sink) { s.redactor = r }
}

// New constructs a Splunk HEC sink. endpoint must be the base URL of the
// Splunk indexer (e.g. "https://splunk.example.com:8088"). token is the
// HEC token; it is sent in the Authorization header as "Splunk <token>".
func New(endpoint, token string, opts ...Option) (*Sink, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("splunkhec: endpoint must not be empty")
	}
	if token == "" {
		return nil, fmt.Errorf("splunkhec: token must not be empty")
	}
	s := &Sink{
		endpoint: endpoint,
		token:    token,
		client:   &http.Client{Timeout: defaultTimeout},
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Name returns the sink identifier used in logs and metrics.
func (s *Sink) Name() string { return "splunk-hec" }

// Stream sends the batch to Splunk HEC. Each event is encoded as a
// separate HEC envelope; all envelopes are concatenated and sent in one
// HTTP request. Returns an error for any non-2xx response or network
// failure.
func (s *Sink) Stream(ctx context.Context, batch []models.AuditEvent) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, evt := range batch {
		if s.redactor != nil {
			evt = s.redactor(evt)
		}
		env := hecEvent{
			Event:      evt,
			Source:     "theauth-go",
			Sourcetype: "_json",
		}
		if err := enc.Encode(env); err != nil {
			return fmt.Errorf("splunkhec: encode: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.endpoint+"/services/collector/event", &buf)
	if err != nil {
		return fmt.Errorf("splunkhec: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("splunkhec: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("splunkhec: unexpected status %d", resp.StatusCode)
	}
	return nil
}
