package memory

import (
	"bytes"
	"context"
	"sort"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

var (
	_ theauth.SessionManagementStorage = (*Store)(nil)
	_ theauth.SessionLinkStorage       = (*Store)(nil)
)

func live(s theauth.Session, now time.Time) bool { return !s.Expired(now) }

// ListUserSessions implements theauth.SessionManagementStorage.
func (s *Store) ListUserSessions(_ context.Context, userID theauth.ULID) ([]theauth.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var out []theauth.Session
	for _, sess := range s.sessions {
		if sess.UserID == userID && live(sess, now) {
			out = append(out, sess)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// TouchSession implements theauth.SessionManagementStorage.
func (s *Store) TouchSession(_ context.Context, id theauth.ULID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return storage.ErrNotFound
	}
	if at.After(sess.LastSeenAt) {
		sess.LastSeenAt = at
		s.sessions[id] = sess
	}
	return nil
}

// RevokeOtherUserSessions implements theauth.SessionManagementStorage.
func (s *Store) RevokeOtherUserSessions(_ context.Context, userID, keep theauth.ULID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := 0
	for id, sess := range s.sessions {
		if sess.UserID == userID && id != keep && live(sess, now) {
			sess.RevokedAt = &now
			s.sessions[id] = sess
			n++
		}
	}
	return n, nil
}

// RevokeSessionsByCredential implements theauth.SessionManagementStorage.
func (s *Store) RevokeSessionsByCredential(_ context.Context, credentialID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := 0
	for id, sess := range s.sessions {
		if sess.CredentialID == credentialID && live(sess, now) {
			sess.RevokedAt = &now
			s.sessions[id] = sess
			n++
		}
	}
	return n, nil
}

// SetSessionElevatedUntil implements theauth.SessionManagementStorage.
func (s *Store) SetSessionElevatedUntil(_ context.Context, id theauth.ULID, until *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return storage.ErrNotFound
	}
	if until != nil {
		u := *until
		until = &u
	}
	sess.ElevatedUntil = until
	s.sessions[id] = sess
	return nil
}

// CreateSessionLink implements theauth.SessionLinkStorage.
func (s *Store) CreateSessionLink(_ context.Context, l theauth.SessionLink) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessionLinks == nil {
		s.sessionLinks = map[theauth.ULID]theauth.SessionLink{}
	}
	s.sessionLinks[l.ID] = l
	return nil
}

// ConsumeSessionLink implements theauth.SessionLinkStorage.
func (s *Store) ConsumeSessionLink(_ context.Context, tokenHash []byte, now time.Time) (*theauth.SessionLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, l := range s.sessionLinks {
		if !bytes.Equal(l.TokenHash, tokenHash) {
			continue
		}
		if l.ConsumedAt != nil || !now.Before(l.ExpiresAt) {
			return nil, storage.ErrNotFound
		}
		l.ConsumedAt = &now
		s.sessionLinks[id] = l
		return &l, nil
	}
	return nil, storage.ErrNotFound
}
