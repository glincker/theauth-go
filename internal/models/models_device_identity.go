package models

import (
	"errors"
	"time"
)

// Device statuses.
const (
	DeviceStatusActive  = "active"
	DeviceStatusRevoked = "revoked"
)

// DeviceAttestationJoinToken is the attestation kind of a device enrolled
// with a single-use join token.
const DeviceAttestationJoinToken = "join_token"

// Device is a registered constrained device. It authenticates to the token
// endpoint with an RFC 7523 assertion signed by the key in PublicKeyJWK.
type Device struct {
	ID ULID
	// OrganizationID scopes the device to one organization. Nil when it was
	// enrolled through the programmatic API without one.
	OrganizationID *ULID
	Name           string
	// SPIFFEID is the workload identity used as the access token subject.
	// Empty when the operator did not assign one.
	SPIFFEID string
	// PublicKeyJWK is the device's public key as a JWK document.
	PublicKeyJWK []byte
	// KeyThumbprint is the RFC 7638 SHA-256 thumbprint of PublicKeyJWK.
	KeyThumbprint string
	// Attestation records how the device proved its identity at enrollment.
	Attestation string
	// Scopes caps what the device's tokens may carry.
	Scopes     []string
	Status     string
	CreatedAt  time.Time
	LastSeenAt *time.Time
	RevokedAt  *time.Time
}

// Active reports whether the device may still obtain tokens.
func (d Device) Active() bool {
	return d.Status == DeviceStatusActive && d.RevokedAt == nil
}

// Subject is the access token sub for the device: the SPIFFE ID when set,
// otherwise device:<id>.
func (d Device) Subject() string {
	if d.SPIFFEID != "" {
		return d.SPIFFEID
	}
	return DeviceSubjectPrefix + d.ID.String()
}

// DeviceSubjectPrefix is prepended to a device ID for the access token sub
// when the device has no SPIFFE ID.
const DeviceSubjectPrefix = "device:"

// DeviceJoinToken is a single-use enrollment secret minted by an admin. It
// fixes the identity the enrolling device receives, so the device never
// chooses its own name, SPIFFE ID or scopes. Stored only as a SHA-256 digest.
type DeviceJoinToken struct {
	ID             ULID
	TokenHash      []byte
	Prefix         string
	OrganizationID *ULID
	Name           string
	SPIFFEID       string
	Scopes         []string
	CreatedBy      *ULID
	CreatedAt      time.Time
	ExpiresAt      time.Time
	// RedeemedAt and DeviceID are set when the token enrolled a device.
	RedeemedAt *time.Time
	DeviceID   *ULID
	RevokedAt  *time.Time
}

// Active reports whether the token can still enroll a device at now.
func (t DeviceJoinToken) Active(now time.Time) bool {
	return t.RedeemedAt == nil && t.RevokedAt == nil && now.Before(t.ExpiresAt)
}

// Device identity sentinels.
var (
	// ErrDeviceEnrollmentInvalid covers unknown, revoked and mismatched devices and
	// join tokens so callers cannot tell which.
	ErrDeviceEnrollmentInvalid = errors.New("theauth: invalid device or join token")
	// ErrDeviceConflict is returned when a SPIFFE ID is already registered.
	ErrDeviceConflict = errors.New("theauth: device SPIFFE ID already registered")
	// ErrDevicesDisabled is returned when device tokens are not configured or
	// the storage cannot hold devices.
	ErrDevicesDisabled = errors.New("theauth: device tokens not enabled")
)
