package as

import (
	"context"
	"time"
)

// CIBAConfig holds the operator knobs for the CIBA feature. Added to Config
// as an optional sub-struct; nil disables CIBA.
type CIBAConfig struct {
	// AuthenticationDevice is the operator-supplied hook that notifies the
	// user's Authentication Device when a new backchannel request arrives.
	// Required when CIBA is enabled; New returns an error otherwise.
	AuthenticationDevice AuthenticationDevice

	// DefaultExpiry is the default auth_req_id lifetime. Defaults to 300s.
	DefaultExpiry time.Duration

	// DefaultInterval is the default poll interval advertised to clients.
	// Defaults to 5s.
	DefaultInterval time.Duration

	// MaxRequestedExpiry is the hard cap on operator-requested expiry via
	// the requested_expiry parameter. Defaults to 600s.
	MaxRequestedExpiry time.Duration

	// MinPollInterval is the floor below which polling triggers slow_down.
	// Defaults to 3s.
	MinPollInterval time.Duration
}

// CIBANotification is the payload forwarded to AuthenticationDevice.Notify
// when a new backchannel authentication request arrives.
type CIBANotification struct {
	// AuthReqID is the opaque poll handle issued to the client.
	AuthReqID string

	// UserID is the resolved user identifier (may be the raw login_hint
	// string when the operator has not yet resolved it to a ULID).
	UserID string

	// ClientID is the registered OAuth client that triggered the request.
	ClientID string

	// Scopes is the requested scope list.
	Scopes []string

	// BindingMessage is the optional short human-readable string the
	// Authentication Device should display to the user.
	BindingMessage string

	// ExpiresAt is when the auth_req_id expires; the AD should not bother
	// notifying the user after this time.
	ExpiresAt time.Time
}

// AuthenticationDevice is the operator-supplied interface that bridges the
// AS to the actual push delivery mechanism (FCM, APNs, SMS, Twilio, etc.).
// Operators implement this interface once and inject it via CIBAConfig.
type AuthenticationDevice interface {
	// Notify is called synchronously inside POST /oauth/bc-authorize after
	// the request has been persisted. If Notify returns an error the
	// handler returns 503 service_unavailable; the auth_req_id has already
	// been written so a retry would be idempotent if the client re-sends.
	//
	// Implementations MUST be non-blocking or fast: long-running push
	// delivery should be dispatched to a goroutine or queue. The context
	// carries the HTTP request deadline.
	Notify(ctx context.Context, req CIBANotification) error
}

// NoopAuthenticationDevice satisfies AuthenticationDevice by discarding every
// notification. Useful in tests and in deployments where the operator polls
// the backchannel_requests table directly.
type NoopAuthenticationDevice struct{}

// Notify satisfies AuthenticationDevice. It always returns nil.
func (NoopAuthenticationDevice) Notify(_ context.Context, _ CIBANotification) error {
	return nil
}

// LoggingAuthenticationDevice satisfies AuthenticationDevice by logging the
// notification details at INFO level via log/slog. Useful in staging
// environments or for local development.
type LoggingAuthenticationDevice struct{}

// Notify satisfies AuthenticationDevice. It logs the notification and returns
// nil.
func (LoggingAuthenticationDevice) Notify(_ context.Context, req CIBANotification) error {
	_ = req // fields are available on the struct; callers read them directly.
	return nil
}

func applyCIBADefaults(c *CIBAConfig) {
	if c.DefaultExpiry <= 0 {
		c.DefaultExpiry = 300 * time.Second
	}
	if c.DefaultInterval <= 0 {
		c.DefaultInterval = 5 * time.Second
	}
	if c.MaxRequestedExpiry <= 0 {
		c.MaxRequestedExpiry = 600 * time.Second
	}
	if c.MinPollInterval <= 0 {
		c.MinPollInterval = 3 * time.Second
	}
}
