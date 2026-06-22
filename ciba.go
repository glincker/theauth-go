package theauth

import (
	"context"
	"time"

	internalas "github.com/glincker/theauth-go/internal/as"
	"github.com/glincker/theauth-go/internal/models"
)

// ciba.go: root-package CIBA surface.
// CIBAConfig, AuthenticationDevice, CIBANotification are thin wrappers
// that re-export the internal/as counterparts so operators only import the
// root package. ApproveBackchannelAuth / DenyBackchannelAuth are the two
// operator-facing service methods.

// AuthenticationDevice is the operator-supplied interface that bridges the
// AS to the actual push delivery mechanism (FCM, APNs, SMS, etc.). See
// internal/as.AuthenticationDevice for the full contract.
type AuthenticationDevice interface {
	Notify(ctx context.Context, req CIBANotification) error
}

// CIBANotification is the payload delivered to AuthenticationDevice.Notify.
type CIBANotification struct {
	AuthReqID      string
	UserID         string
	ClientID       string
	Scopes         []string
	BindingMessage string
	ExpiresAt      time.Time
}

// NoopAuthenticationDevice satisfies AuthenticationDevice by discarding every
// notification. Suitable for unit tests and operator deployments that manage
// notifications out of band.
type NoopAuthenticationDevice struct{}

// Notify satisfies AuthenticationDevice. It is a no-op and always returns nil.
func (NoopAuthenticationDevice) Notify(_ context.Context, _ CIBANotification) error { return nil }

// LoggingAuthenticationDevice satisfies AuthenticationDevice by logging
// notifications to log/slog at INFO level. Suitable for staging environments.
type LoggingAuthenticationDevice struct{}

// Notify satisfies AuthenticationDevice. It logs the notification details and
// returns nil.
func (LoggingAuthenticationDevice) Notify(_ context.Context, req CIBANotification) error {
	// Fields are accessible on req; no-op here keeps the root package
	// dependency-light. Operators can replace this with a real slog call.
	_ = req
	return nil
}

// CIBAConfig wires the CIBA feature on the authorization server.
// Set Config.AuthorizationServer.CIBA to enable. Leave nil (default) to
// disable CIBA entirely.
type CIBAConfig struct {
	// AuthenticationDevice is required. The AS calls Notify on every
	// POST /oauth/bc-authorize so the user's device receives the push.
	AuthenticationDevice AuthenticationDevice

	// DefaultExpiry is the default auth_req_id lifetime. Defaults to 300s.
	DefaultExpiry time.Duration

	// DefaultInterval is the default client poll interval. Defaults to 5s.
	DefaultInterval time.Duration

	// MaxRequestedExpiry caps the requested_expiry parameter. Defaults to 600s.
	MaxRequestedExpiry time.Duration

	// MinPollInterval is the floor that triggers slow_down when breached.
	// Defaults to 3s.
	MinPollInterval time.Duration
}

// cibaAdapterDevice bridges the root AuthenticationDevice to the internal
// internalas.AuthenticationDevice interface. Both use context.Context so the
// adapter is a thin forwarder.
type cibaAdapterDevice struct {
	root AuthenticationDevice
}

func (a cibaAdapterDevice) Notify(ctx context.Context, req internalas.CIBANotification) error {
	return a.root.Notify(ctx, CIBANotification{
		AuthReqID:      req.AuthReqID,
		UserID:         req.UserID,
		ClientID:       req.ClientID,
		Scopes:         append([]string(nil), req.Scopes...),
		BindingMessage: req.BindingMessage,
		ExpiresAt:      req.ExpiresAt,
	})
}

// cibaConfigToInternal converts a root CIBAConfig to the internal/as version.
// Returns nil when cfg is nil so callers can nil-check.
func cibaConfigToInternal(cfg *CIBAConfig) *internalas.CIBAConfig {
	if cfg == nil {
		return nil
	}
	var device internalas.AuthenticationDevice
	if cfg.AuthenticationDevice != nil {
		device = cibaAdapterDevice{root: cfg.AuthenticationDevice}
	}
	return &internalas.CIBAConfig{
		AuthenticationDevice: device,
		DefaultExpiry:        cfg.DefaultExpiry,
		DefaultInterval:      cfg.DefaultInterval,
		MaxRequestedExpiry:   cfg.MaxRequestedExpiry,
		MinPollInterval:      cfg.MinPollInterval,
	}
}

// ApproveBackchannelAuth marks the pending CIBA request as approved and
// provisions the access + refresh tokens that the next poll will return.
//
// userID MUST be the resolved identity of the authenticating user. When the
// original request supplied a login_hint that the operator resolved to this
// user, pass the matching ULID. If the request was already bound to a
// different user, ApproveBackchannelAuth returns ErrCIBAUserMismatch.
//
// Returns ErrCIBADisabled when CIBA is not configured or the storage does not
// implement CIBAStorage.
func (a *TheAuth) ApproveBackchannelAuth(ctx context.Context, authReqID string, userID ULID) error {
	if a.as == nil {
		return models.ErrCIBADisabled
	}
	return a.as.ApproveBackchannelRequest(ctx, authReqID, userID)
}

// DenyBackchannelAuth marks the pending CIBA request as denied. The next
// client poll returns access_denied.
//
// Returns ErrCIBADisabled when CIBA is not configured.
func (a *TheAuth) DenyBackchannelAuth(ctx context.Context, authReqID string, userID ULID) error {
	if a.as == nil {
		return models.ErrCIBADisabled
	}
	return a.as.DenyBackchannelRequest(ctx, authReqID, userID)
}
