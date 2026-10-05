package theauth

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// SessionLink is a short-lived, single-use grant that exchanges for a session.
type SessionLink = models.SessionLink

// SessionManagementStorage is the optional capability behind end-user session
// lists, idle timeout, last-seen tracking and step-up. It is detected by type
// assertion and is not part of Storage.
type SessionManagementStorage interface {
	// ListUserSessions returns the user's sessions that are neither revoked
	// nor past ExpiresAt, newest first.
	ListUserSessions(ctx context.Context, userID ULID) ([]Session, error)
	// TouchSession advances LastSeenAt to at. It never moves it backwards
	// and returns ErrStorageNotFound for an unknown id.
	TouchSession(ctx context.Context, id ULID, at time.Time) error
	// RevokeOtherUserSessions revokes every live session of userID except
	// keep and returns how many it revoked.
	RevokeOtherUserSessions(ctx context.Context, userID, keep ULID) (int, error)
	// RevokeSessionsByCredential revokes every live session tied to
	// credentialID and returns how many it revoked.
	RevokeSessionsByCredential(ctx context.Context, credentialID string) (int, error)
	// SetSessionElevatedUntil sets or clears ElevatedUntil on one session.
	SetSessionElevatedUntil(ctx context.Context, id ULID, until *time.Time) error
}

// SessionLinkStorage is the optional capability behind programmatic session
// links.
type SessionLinkStorage interface {
	CreateSessionLink(ctx context.Context, l SessionLink) error
	// ConsumeSessionLink atomically marks the link used and returns it. It
	// returns ErrStorageNotFound when the hash is unknown, already used, or
	// expired at now.
	ConsumeSessionLink(ctx context.Context, tokenHash []byte, now time.Time) (*SessionLink, error)
}
