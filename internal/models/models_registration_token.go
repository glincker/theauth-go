package models

import (
	"errors"
	"time"
)

// RegistrationToken is an initial access token (RFC 7591 section 1.2) for
// POST /oauth/register. Tokens are created through the admin API, shown once,
// and stored only as a SHA-256 digest. The token is 256 random bits, so a
// plain digest is sufficient at rest.
type RegistrationToken struct {
	ID ULID
	// TokenHash is sha256 of the token string.
	TokenHash []byte
	// Prefix is the first characters of the token, kept so operators can
	// recognize a token in lists without the secret being recoverable.
	Prefix string
	Label  string
	// OrganizationID scopes the token to one organization's admin view. Nil
	// for tokens created through the programmatic API without an org.
	OrganizationID *ULID
	// Scopes caps the scope a client registered with this token may request.
	// Empty means no scope restriction.
	Scopes []string
	// GrantTypes caps the grant types the registered client may declare.
	// Empty means no restriction.
	GrantTypes []string
	// MaxUses is how many registrations the token allows. 1 makes it one-time.
	MaxUses    int
	Uses       int
	CreatedBy  *ULID
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// Active reports whether the token can still be redeemed at now.
func (t RegistrationToken) Active(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt) && t.Uses < t.MaxUses
}

// Registration token sentinels.
var (
	// ErrRegistrationTokenInvalid covers unknown, expired, revoked and
	// exhausted tokens so callers cannot tell which.
	ErrRegistrationTokenInvalid = errors.New("theauth: invalid registration token")
	// ErrRegistrationTokenScope is returned when the registration request asks
	// for more than the token allows.
	ErrRegistrationTokenScope = errors.New("theauth: registration request exceeds token scope")
	// ErrRegistrationTokensDisabled is returned when the storage does not
	// implement RegistrationTokenStorage.
	ErrRegistrationTokensDisabled = errors.New("theauth: registration tokens not supported by storage")
)
