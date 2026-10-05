package models

import (
	"errors"
	"time"
)

// SessionLink is a short-lived, single-use grant that exchanges for a session
// on behalf of UserID. Only the sha256 of the token is stored.
type SessionLink struct {
	ID        ULID   `json:"id"`
	UserID    ULID   `json:"userId"`
	TokenHash []byte `json:"-"`
	// CredentialID ties the resulting session to an upstream credential that
	// is re-checked on every session use. Empty for an unbound link.
	CredentialID string `json:"credentialId,omitempty"`
	// SessionTTL bounds the resulting session; zero means the default TTL.
	SessionTTL time.Duration `json:"sessionTtl,omitempty"`
	CreatedAt  time.Time     `json:"createdAt"`
	ExpiresAt  time.Time     `json:"expiresAt"`
	ConsumedAt *time.Time    `json:"consumedAt,omitempty"`
}

var (
	// ErrCredentialRevoked is returned by a CredentialChecker when the
	// upstream credential a session is tied to is revoked, expired or gone.
	ErrCredentialRevoked = errors.New("theauth: upstream credential revoked")

	// ErrSessionLinkInvalid covers every way a session link fails to
	// exchange: unknown, expired, already used, or credential revoked.
	ErrSessionLinkInvalid = errors.New("theauth: invalid or expired session link")
)
