package theauth

import (
	"context"
	"errors"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
)

// issueSession mints a fresh opaque token, stores its sha256 hash with a new
// Session row, and returns the raw token. The raw token is what the caller
// puts in a cookie / sends to the user; the hash is what's persisted.
func (a *TheAuth) issueSession(ctx context.Context, user User, userAgent, ip string) (token string, sess Session, err error) {
	token, err = crypto.NewToken()
	if err != nil {
		return "", Session{}, err
	}
	now := time.Now()
	sess = Session{
		ID:        ulid.New(),
		UserID:    user.ID,
		TokenHash: crypto.HashToken(token),
		UserAgent: userAgent,
		IP:        ip,
		CreatedAt: now,
		ExpiresAt: now.Add(a.sessionTTL),
	}
	sess, err = a.storage.CreateSession(ctx, sess)
	if err != nil {
		return "", Session{}, err
	}
	return token, sess, nil
}

// validateSession looks up a session by the hash of the supplied token,
// verifies it isn't expired or revoked, and returns the session and its user.
// Returns ErrInvalidToken for missing/unknown tokens and ErrSessionExpired
// for expired or revoked sessions.
func (a *TheAuth) validateSession(ctx context.Context, token string) (*Session, *User, error) {
	if token == "" {
		return nil, nil, ErrInvalidToken
	}
	sess, err := a.storage.SessionByTokenHash(ctx, crypto.HashToken(token))
	if errors.Is(err, ErrStorageNotFound) {
		return nil, nil, ErrInvalidToken
	}
	if err != nil {
		return nil, nil, err
	}
	if sess.Expired(time.Now()) {
		return nil, nil, ErrSessionExpired
	}
	user, err := a.storage.UserByID(ctx, sess.UserID)
	if err != nil {
		return nil, nil, err
	}
	return sess, user, nil
}
