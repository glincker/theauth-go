package storage

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go"
)

// ErrNotFound is returned by storage adapters when a lookup misses.
// Service code translates to theauth sentinel errors as appropriate.
var ErrNotFound = errors.New("storage: not found")

type Storage interface {
	// Users
	CreateUser(ctx context.Context, u theauth.User) (theauth.User, error)
	UserByEmail(ctx context.Context, email string) (*theauth.User, error)
	UserByID(ctx context.Context, id theauth.ULID) (*theauth.User, error)
	MarkEmailVerified(ctx context.Context, userID theauth.ULID) error

	// Sessions
	CreateSession(ctx context.Context, s theauth.Session) (theauth.Session, error)
	SessionByTokenHash(ctx context.Context, hash []byte) (*theauth.Session, error)
	RevokeSession(ctx context.Context, id theauth.ULID) error
	RevokeUserSessions(ctx context.Context, userID theauth.ULID) error

	// Magic links
	CreateMagicLink(ctx context.Context, ml theauth.MagicLink) error
	ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*theauth.MagicLink, error)
}
