// Package webhook provides an AuditSink that POSTs audit events as CloudEvents 1.0 envelopes,
// HMAC-SHA256 signed. Verify rejects stale timestamps to bound replay.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

const defaultTimeout = 5 * time.Second

// cloudEvent is a CloudEvents 1.0 envelope.
type cloudEvent struct {
	SpecVersion     string            `json:"specversion"`
	Type            string            `json:"type"`
	Source          string            `json:"source"`
	ID              string            `json:"id"`
	Time            time.Time         `json:"time"`
	DataContentType string            `json:"datacontenttype"`
	Data            models.AuditEvent `json:"data"`
}

// Sink is an AuditSink that streams to a generic CloudEvents 1.0 webhook.
type Sink struct {
	endpoint   string
	hmacSecret []byte
	client     *http.Client
	redactor   func(models.AuditEvent) models.AuditEvent
	now        func() time.Time
}

// SignatureHeader and TimestampHeader name the headers carrying the MAC and send time.
const (
	SignatureHeader = "X-CloudEvents-Signature"
	TimestampHeader = "X-CloudEvents-Timestamp"
	// DefaultReplayWindow is the tolerance Verify callers should start with.
	DefaultReplayWindow = 5 * time.Minute
)

// Verification errors returned by Verify.
var (
	ErrSignatureMissing  = errors.New("webhook: signature or timestamp header missing")
	ErrSignatureMismatch = errors.New("webhook: signature mismatch")
	ErrTimestampStale    = errors.New("webhook: timestamp outside replay window")
)

// Verify recomputes the MAC over "<timestamp>."+body in constant time and rejects
// timestamps further than window from now (DefaultReplayWindow when window <= 0).
func Verify(secret, body []byte, signature, timestamp string, window time.Duration, now time.Time) error {
	if signature == "" || timestamp == "" {
		return ErrSignatureMissing
	}
	if window <= 0 {
		window = DefaultReplayWindow
	}
	secs, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrSignatureMissing
	}
	got, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return ErrSignatureMismatch
	}
	if !hmac.Equal(got, sign(secret, timestamp, body)) {
		return ErrSignatureMismatch
	}
	if d := now.Sub(time.Unix(secs, 0)); d > window || d < -window {
		return ErrTimestampStale
	}
	return nil
}

func sign(secret []byte, timestamp string, body []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return mac.Sum(nil)
}

// WithClock overrides the time source used to stamp requests (tests).
func WithClock(now func() time.Time) Option {
	return func(s *Sink) { s.now = now }
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

// New constructs a webhook sink POSTing to endpoint. A nil or empty hmacSecret disables
// signing, which is not recommended for production.
func New(endpoint string, hmacSecret []byte, opts ...Option) (*Sink, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("webhook: endpoint must not be empty")
	}
	s := &Sink{
		endpoint:   endpoint,
		hmacSecret: hmacSecret,
		client:     &http.Client{Timeout: defaultTimeout},
		now:        time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Name returns the sink identifier used in logs and metrics.
func (s *Sink) Name() string { return "webhook" }

// Stream POSTs each event as its own CloudEvents request, attempting every event and
// returning the first error.
func (s *Sink) Stream(ctx context.Context, batch []models.AuditEvent) error {
	var firstErr error
	for _, evt := range batch {
		if s.redactor != nil {
			evt = s.redactor(evt)
		}
		if err := s.send(ctx, evt); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Sink) send(ctx context.Context, evt models.AuditEvent) error {
	ce := cloudEvent{
		SpecVersion:     "1.0",
		Type:            "com.theauth.audit.v1." + evt.Action,
		Source:          "theauth-go",
		ID:              newRequestID(),
		Time:            evt.CreatedAt,
		DataContentType: "application/json",
		Data:            evt,
	}
	body, err := json.Marshal(ce)
	if err != nil {
		return fmt.Errorf("webhook: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/cloudevents+json")
	if len(s.hmacSecret) > 0 {
		ts := strconv.FormatInt(s.now().Unix(), 10)
		req.Header.Set(TimestampHeader, ts)
		req.Header.Set(SignatureHeader, "sha256="+hex.EncodeToString(sign(s.hmacSecret, ts, body)))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// newRequestID returns a random hex CloudEvents event ID.
func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("webhook: entropy failure: " + err.Error())
	}
	return hex.EncodeToString(b)
}
