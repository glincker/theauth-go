package models

import (
	"errors"
	"time"
)

// RFC 8628 OAuth 2.0 Device Authorization Grant, served by the authorization
// server at POST /oauth/device_authorization and the device_code grant of
// POST /oauth/token. This is separate from the API-token device flow in
// internal/apitokens (DeviceCode), which mints long-lived API tokens.

// GrantTypeDeviceCode is the RFC 8628 section 3.4 grant type URN.
const GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceAuthorization status values.
const (
	DeviceAuthPending  = "pending"
	DeviceAuthApproved = "approved"
	DeviceAuthDenied   = "denied"
	// DeviceAuthConsumed marks an approved authorization whose tokens were
	// already issued. The transition approved to consumed is atomic, which
	// makes a device_code single use.
	DeviceAuthConsumed = "consumed"
)

// DeviceAuthorization is the persistent record of one device flow. Neither
// code is stored in clear: DeviceCodeHash and UserCodeHash are keyed hashes
// (HMAC-SHA256 under a server secret), so a database leak does not reveal
// codes that are still live.
type DeviceAuthorization struct {
	ID             ULID
	DeviceCodeHash []byte
	UserCodeHash   []byte
	ClientID       string
	Scope          []string
	// Resource is the RFC 8707 audience the tokens will be minted for. May
	// be empty, in which case the AS default applies at redemption.
	Resource string
	Status   string
	// UserID is set when the user approves or denies.
	UserID *ULID
	// IntervalSeconds is the current minimum polling interval. It grows by
	// five seconds each time the client is told slow_down (RFC 8628 3.5).
	IntervalSeconds int
	LastPollAt      *time.Time
	CreatedAt       time.Time
	ExpiresAt       time.Time
	DecidedAt       *time.Time
}

// RFC 8628 section 3.5 error sentinels.
var (
	// ErrDeviceAuthorizationPending maps to authorization_pending.
	ErrDeviceAuthorizationPending = errors.New("theauth: authorization_pending (device)")
	// ErrDeviceSlowDown maps to slow_down.
	ErrDeviceSlowDown = errors.New("theauth: slow_down (device)")
	// ErrDeviceAccessDenied maps to access_denied.
	ErrDeviceAccessDenied = errors.New("theauth: access_denied (device)")
	// ErrDeviceExpiredToken maps to expired_token.
	ErrDeviceExpiredToken = errors.New("theauth: expired_token (device)")
	// ErrDeviceAuthDisabled is returned when the device grant is not configured
	// or the storage does not implement DeviceAuthorizationStorage.
	ErrDeviceAuthDisabled = errors.New("theauth: device authorization not enabled")
	// ErrDeviceAuthUserCodeTaken is returned by InsertDeviceAuthorization when
	// the user code hash collides with a live record. The service retries
	// with a fresh code.
	ErrDeviceAuthUserCodeTaken = errors.New("theauth: device authorization user code already in use")
	// ErrDeviceUserCodeInvalid is returned for an unknown, expired or
	// already decided user code. One error covers all three so the
	// verification page cannot be used to probe which codes exist.
	ErrDeviceUserCodeInvalid = errors.New("theauth: invalid or expired user code")
	// ErrDeviceTooManyAttempts is returned when a subject exceeded the
	// user-code attempt budget.
	ErrDeviceTooManyAttempts = errors.New("theauth: too many user code attempts")
)
