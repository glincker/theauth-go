package memory

import (
	"context"
	"sync"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

// memory_ciba.go: in-memory CIBAStorage adapter for RFC 9509 backchannel
// authentication. State lives in a sidecar struct to keep Store{} small.

type cibaState struct {
	mu       sync.RWMutex
	requests map[string]theauth.BackchannelRequest // keyed by auth_req_id
}

func (s *Store) ensureCIBA() *cibaState {
	if s.ciba == nil {
		s.ciba = &cibaState{
			requests: map[string]theauth.BackchannelRequest{},
		}
	}
	return s.ciba
}

// InsertBackchannelRequest satisfies CIBAStorage.
func (s *Store) InsertBackchannelRequest(_ context.Context, req theauth.BackchannelRequest) error {
	c := s.ensureCIBA()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.requests[req.AuthReqID]; dup {
		return storage.ErrNotFound
	}
	if req.CreatedAt.IsZero() {
		req.CreatedAt = time.Now()
	}
	c.requests[req.AuthReqID] = req
	return nil
}

// BackchannelRequestByID satisfies CIBAStorage.
func (s *Store) BackchannelRequestByID(_ context.Context, authReqID string) (theauth.BackchannelRequest, error) {
	c := s.ensureCIBA()
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.requests[authReqID]
	if !ok {
		return theauth.BackchannelRequest{}, storage.ErrNotFound
	}
	return r, nil
}

// UpdateBackchannelRequest satisfies CIBAStorage.
func (s *Store) UpdateBackchannelRequest(_ context.Context, req theauth.BackchannelRequest) error {
	c := s.ensureCIBA()
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, ok := c.requests[req.AuthReqID]
	if !ok {
		return storage.ErrNotFound
	}
	// Preserve immutable fields.
	req.CreatedAt = existing.CreatedAt
	c.requests[req.AuthReqID] = req
	return nil
}

// DeleteBackchannelRequest satisfies CIBAStorage.
func (s *Store) DeleteBackchannelRequest(_ context.Context, authReqID string) error {
	c := s.ensureCIBA()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.requests[authReqID]; !ok {
		return storage.ErrNotFound
	}
	delete(c.requests, authReqID)
	return nil
}

// TouchBackchannelPoll satisfies CIBAStorage. It updates LastPollAt and
// PollInterval atomically and returns the updated row.
func (s *Store) TouchBackchannelPoll(_ context.Context, authReqID string, now time.Time, newInterval int) (theauth.BackchannelRequest, error) {
	c := s.ensureCIBA()
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.requests[authReqID]
	if !ok {
		return theauth.BackchannelRequest{}, storage.ErrNotFound
	}
	r.LastPollAt = &now
	r.PollInterval = newInterval
	c.requests[authReqID] = r
	return r, nil
}
