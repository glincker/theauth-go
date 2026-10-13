package models

import (
	"errors"
	"time"
)

// ErrAccountStateDisabled is returned by the forced-password-change and
// disable APIs when Config.AccountState is false.
var ErrAccountStateDisabled = errors.New("theauth: Config.AccountState is not enabled")

// Codes added with the account lifecycle work. Additive: no existing code changed.
const (
	// CodePasswordChangeRequired is returned at sign-in when the account is
	// flagged MustChangePassword. The credential was correct; the caller must
	// complete a password reset before a session is issued.
	CodePasswordChangeRequired = "password_change_required"
	// CodeAccountDisabled is returned at sign-in when the account is disabled.
	CodeAccountDisabled = "account_disabled"
	// CodeReauthRequired is returned by self-service destructive actions when
	// the session was not recently authenticated.
	CodeReauthRequired = "reauth_required"
	// CodeSessionLimit is returned when SessionPolicy.MaxConcurrentSessions is
	// reached and the policy is reject.
	CodeSessionLimit = "session_limit_reached"
	// CodeProviderGrantRevoked is returned when the upstream provider no
	// longer honors the stored refresh token.
	CodeProviderGrantRevoked = "provider_grant_revoked"
	// CodeProviderNoRefresh is returned when the provider or the stored grant
	// cannot be refreshed.
	CodeProviderNoRefresh = "provider_refresh_unsupported"
)

// AccountState holds per-user lifecycle flags kept outside the user row so
// adding them never touches the user queries of an adapter.
type AccountState struct {
	// MustChangePassword blocks sign-in until the password is changed or reset.
	MustChangePassword bool
	// DisabledAt, when set, blocks sign-in and has revoked every session.
	DisabledAt *time.Time
}

// TrustedDevice is a remember-this-device record that lets a password
// sign-in skip the TOTP prompt. Only the SHA-256 of the cookie token is stored.
type TrustedDevice struct {
	ID         ULID       `json:"id"`
	UserID     ULID       `json:"userId"`
	TokenHash  []byte     `json:"-"`
	Label      string     `json:"label"`
	UserAgent  string     `json:"-"`
	IP         string     `json:"-"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt time.Time  `json:"lastUsedAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

// Upstream provider token sentinels. They are wrapped in a TheAuthError with
// the matching Code, so both errors.Is on the sentinel and on a code-only
// TheAuthError work.
var (
	// ErrProviderGrantRevoked means the provider no longer honors the stored
	// refresh token (user revoked access, token expired or rotated away). The
	// stored tokens are cleared; the user must sign in with the provider again.
	ErrProviderGrantRevoked = errors.New("theauth: provider grant revoked")
	// ErrProviderRefreshUnsupported means the provider cannot refresh tokens,
	// or no refresh token is stored for the account.
	ErrProviderRefreshUnsupported = errors.New("theauth: provider token refresh unsupported")
	// ErrProviderNotLinked means the user has no linked account for the provider.
	ErrProviderNotLinked = errors.New("theauth: provider account not linked")
)
