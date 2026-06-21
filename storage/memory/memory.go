package memory

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

type Store struct {
	mu             sync.RWMutex
	users          map[theauth.ULID]theauth.User
	sessions       map[theauth.ULID]theauth.Session
	magicLinks     map[theauth.ULID]theauth.MagicLink
	passwordHashes map[theauth.ULID]string
	resetTokens    map[theauth.ULID]theauth.PasswordResetToken
	oauthAccounts  map[theauth.ULID]theauth.OAuthAccount
}

func New() *Store {
	return &Store{
		users:          map[theauth.ULID]theauth.User{},
		sessions:       map[theauth.ULID]theauth.Session{},
		magicLinks:     map[theauth.ULID]theauth.MagicLink{},
		passwordHashes: map[theauth.ULID]string{},
		resetTokens:    map[theauth.ULID]theauth.PasswordResetToken{},
		oauthAccounts:  map[theauth.ULID]theauth.OAuthAccount{},
	}
}

func (s *Store) CreateUser(_ context.Context, u theauth.User) (theauth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.ID] = u
	return u, nil
}

func (s *Store) UserByEmail(_ context.Context, email string) (*theauth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Email == email {
			cp := u
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) UserByID(_ context.Context, id theauth.ULID) (*theauth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return &u, nil
}

func (s *Store) MarkEmailVerified(_ context.Context, userID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return storage.ErrNotFound
	}
	now := time.Now()
	u.EmailVerifiedAt = &now
	s.users[userID] = u
	return nil
}

func (s *Store) CreateSession(_ context.Context, sess theauth.Session) (theauth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return sess, nil
}

func (s *Store) SessionByTokenHash(_ context.Context, hash []byte) (*theauth.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.sessions {
		if bytes.Equal(sess.TokenHash, hash) {
			cp := sess
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) RevokeSession(_ context.Context, id theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return storage.ErrNotFound
	}
	now := time.Now()
	sess.RevokedAt = &now
	s.sessions[id] = sess
	return nil
}

func (s *Store) RevokeUserSessions(_ context.Context, userID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, sess := range s.sessions {
		if sess.UserID == userID && sess.RevokedAt == nil {
			sess.RevokedAt = &now
			s.sessions[id] = sess
		}
	}
	return nil
}

func (s *Store) CreateMagicLink(_ context.Context, ml theauth.MagicLink) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.magicLinks[ml.ID] = ml
	return nil
}

func (s *Store) ConsumeMagicLink(_ context.Context, hash []byte) (*theauth.MagicLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, ml := range s.magicLinks {
		if bytes.Equal(ml.TokenHash, hash) && ml.UsedAt == nil && !ml.ExpiresAt.Before(now) {
			ml.UsedAt = &now
			s.magicLinks[id] = ml
			cp := ml
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

// ---------- Password credentials (v0.2) ----------

func (s *Store) SetUserPassword(_ context.Context, userID theauth.ULID, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return storage.ErrNotFound
	}
	s.passwordHashes[userID] = passwordHash
	return nil
}

func (s *Store) UserByEmailWithPassword(_ context.Context, email string) (*theauth.User, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Email == email {
			cp := u
			return &cp, s.passwordHashes[u.ID], nil
		}
	}
	return nil, "", storage.ErrNotFound
}

func (s *Store) CreatePasswordResetToken(_ context.Context, t theauth.PasswordResetToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[t.UserID]; !ok {
		return storage.ErrNotFound
	}
	s.resetTokens[t.ID] = t
	return nil
}

func (s *Store) ConsumePasswordResetToken(_ context.Context, hash []byte) (*theauth.PasswordResetToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, rt := range s.resetTokens {
		if bytes.Equal(rt.TokenHash, hash) && rt.UsedAt == nil && !rt.ExpiresAt.Before(now) {
			rt.UsedAt = &now
			s.resetTokens[id] = rt
			cp := rt
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

// ---------- OAuth accounts (v0.3) ----------

// UpsertOAuthAccount mirrors the Postgres ON CONFLICT (provider, provider_user_id)
// DO UPDATE behavior: if a row with the same (provider, provider_user_id)
// already exists, its mutable fields are refreshed in place (keeping the
// original ID + CreatedAt). Otherwise the supplied row is inserted as-is.
func (s *Store) UpsertOAuthAccount(_ context.Context, a theauth.OAuthAccount) (theauth.OAuthAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, existing := range s.oauthAccounts {
		if existing.Provider == a.Provider && existing.ProviderUserID == a.ProviderUserID {
			existing.UserID = a.UserID
			existing.AccessTokenEnc = a.AccessTokenEnc
			existing.RefreshTokenEnc = a.RefreshTokenEnc
			existing.ExpiresAt = a.ExpiresAt
			existing.Scope = a.Scope
			existing.UpdatedAt = now
			s.oauthAccounts[id] = existing
			return existing, nil
		}
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	a.UpdatedAt = now
	s.oauthAccounts[a.ID] = a
	return a, nil
}

func (s *Store) OAuthAccountByProviderUserID(_ context.Context, provider, providerUserID string) (*theauth.OAuthAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.oauthAccounts {
		if a.Provider == provider && a.ProviderUserID == providerUserID {
			cp := a
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}
