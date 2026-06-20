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
	mu         sync.RWMutex
	users      map[theauth.ULID]theauth.User
	sessions   map[theauth.ULID]theauth.Session
	magicLinks map[theauth.ULID]theauth.MagicLink
}

func New() *Store {
	return &Store{
		users:      map[theauth.ULID]theauth.User{},
		sessions:   map[theauth.ULID]theauth.Session{},
		magicLinks: map[theauth.ULID]theauth.MagicLink{},
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
	for id, ml := range s.magicLinks {
		if bytes.Equal(ml.TokenHash, hash) && ml.UsedAt == nil {
			now := time.Now()
			ml.UsedAt = &now
			s.magicLinks[id] = ml
			cp := ml
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}
