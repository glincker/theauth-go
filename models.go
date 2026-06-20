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
