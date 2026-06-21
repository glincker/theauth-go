package theauth

import (
	"time"

	"github.com/oklog/ulid/v2"
)

// ULID is the canonical ID type — generated in app, stored as uuid in Postgres.
type ULID = ulid.ULID

type User struct {
	ID              ULID       `json:"id"`
	Email           string     `json:"email"`
	EmailVerifiedAt *time.Time `json:"emailVerifiedAt,omitempty"`
	Name            string     `json:"name"`
	AvatarURL       string     `json:"avatarUrl"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}

type Session struct {
	ID        ULID       `json:"id"`
	UserID    ULID       `json:"userId"`
	TokenHash []byte     `json:"-"` // never serialize raw hash
	UserAgent string     `json:"userAgent"`
	IP        string     `json:"ip"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
}

// Expired reports whether the session is no longer usable at the given time.
func (s Session) Expired(now time.Time) bool {
	if s.RevokedAt != nil {
		return true
	}
	return !now.Before(s.ExpiresAt)
}

type MagicLink struct {
	ID        ULID       `json:"id"`
	Email     string     `json:"email"`
	TokenHash []byte     `json:"-"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

// PasswordResetToken backs the /auth/email-password/forgot+reset flow. Shape
// mirrors MagicLink but binds to a known user_id (resets always operate on an
// existing account), and lives in its own table to keep flows isolated.
type PasswordResetToken struct {
	ID        ULID       `json:"id"`
	UserID    ULID       `json:"userId"`
	TokenHash []byte     `json:"-"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

// OAuthAccount records the linkage between one of our Users and a remote
// OAuth provider identity (e.g. user X authenticates via GitHub). The
// (provider, provider_user_id) pair is unique; re-running the OAuth flow
// for the same provider account upserts this row rather than creating a
// duplicate. Tokens are encrypted at rest via crypto.Encrypt and are
// never serialized over JSON.
type OAuthAccount struct {
	ID              ULID       `json:"id"`
	UserID          ULID       `json:"userId"`
	Provider        string     `json:"provider"`
	ProviderUserID  string     `json:"providerUserId"`
	AccessTokenEnc  []byte     `json:"-"`
	RefreshTokenEnc []byte     `json:"-"`
	ExpiresAt       *time.Time `json:"expiresAt,omitempty"`
	Scope           string     `json:"scope"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}
