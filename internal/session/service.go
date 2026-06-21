// Package session owns the Issue / Validate primitives for opaque
// session tokens. Extracted from root service_session.go in PR A of the
// 2026-06 architecture reorg.
//
// Tokens themselves are produced by crypto.NewToken and only the sha256
// hash is persisted; the raw token is returned to the caller exactly once
// (typically dropped into a Secure HttpOnly cookie). validate looks up by
// hash, rejects expired or revoked rows, and returns the bound user.
package session

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
)

// Storage is the minimal persistence subset this package needs. Declared
// here (not imported from root) so that internal/session does not import
// github.com/glincker/theauth-go, which would form an import cycle with the
// root constructor.
//
// Any type satisfying these three methods (notably the root theauth.Storage
// interface) is a valid argument to New. Duck-typed against the larger
// root contract by design.
type Storage interface {
	CreateSession(ctx context.Context, s models.Session) (models.Session, error)
	SessionByTokenHash(ctx context.Context, hash []byte) (*models.Session, error)
	UserByID(ctx context.Context, id models.ULID) (*models.User, error)
}

// Service holds the dependencies needed to issue and validate sessions.
// Constructed once in theauth.New and reused for the lifetime of the
// process.
type Service struct {
	storage Storage
	ttl     time.Duration
}

// New constructs a session Service.
func New(storage Storage, ttl time.Duration) *Service {
	return &Service{storage: storage, ttl: ttl}
}

// Issue mints a fresh opaque token, stores its sha256 hash with a new
// Session row, and returns the raw token. The raw token is what the caller
// puts in a cookie / sends to the user; the hash is what's persisted.
func (s *Service) Issue(ctx context.Context, user models.User, userAgent, ip string) (token string, sess models.Session, err error) {
	token, err = crypto.NewToken()
	if err != nil {
		return "", models.Session{}, err
	}
	now := time.Now()
	sess = models.Session{
		ID:        ulid.New(),
		UserID:    user.ID,
		TokenHash: crypto.HashToken(token),
		UserAgent: userAgent,
		IP:        ip,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}
	sess, err = s.storage.CreateSession(ctx, sess)
	if err != nil {
		return "", models.Session{}, err
	}
	slog.Info("theauth: session issued", "user_id", sess.UserID.String(), "session_id", sess.ID.String())
	return token, sess, nil
}

// Validate looks up a session by the hash of the supplied token, verifies
// it is not expired or revoked, and returns the session and its user.
// Returns models.ErrInvalidToken for missing/unknown tokens and
// models.ErrSessionExpired for expired or revoked sessions.
func (s *Service) Validate(ctx context.Context, token string) (*models.Session, *models.User, error) {
	if token == "" {
		return nil, nil, models.ErrInvalidToken
	}
	sess, err := s.storage.SessionByTokenHash(ctx, crypto.HashToken(token))
	if errors.Is(err, models.ErrStorageNotFound) {
		return nil, nil, models.ErrInvalidToken
	}
	if err != nil {
		return nil, nil, err
	}
	if sess.Expired(time.Now()) {
		return nil, nil, models.ErrSessionExpired
	}
	user, err := s.storage.UserByID(ctx, sess.UserID)
	if err != nil {
		return nil, nil, err
	}
	return sess, user, nil
}
