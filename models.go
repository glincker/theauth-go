package theauth

import (
	"time"

	"github.com/oklog/ulid/v2"
)

// ULID is the canonical ID type — generated in app, stored as uuid in Postgres.
type ULID = ulid.ULID

type User struct {
	ID              ULID
	Email           string
	EmailVerifiedAt *time.Time
	Name            string
	AvatarURL       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Session struct {
	ID        ULID
	UserID    ULID
	TokenHash []byte // sha256 of the opaque token
	UserAgent string
	IP        string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Expired reports whether the session is no longer usable at the given time.
func (s Session) Expired(now time.Time) bool {
	if s.RevokedAt != nil {
		return true
	}
	return !now.Before(s.ExpiresAt)
}

type MagicLink struct {
	ID        ULID
	Email     string
	TokenHash []byte
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}
