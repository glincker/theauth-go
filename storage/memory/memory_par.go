package memory

import (
	"context"
	"sync"
	"time"

	"github.com/glincker/theauth-go/storage"
)

// memory_par.go: in-memory PARStorage implementation for RFC 9126.

// pushedRequest holds one stored pushed authorization request.
type pushedRequest struct {
	payload   []byte
	expiresAt time.Time
}

// parState holds the PAR storage sub-state. Kept separate so the
// memory.Store literal stays compact.
type parState struct {
	mu       sync.Mutex
	requests map[string]pushedRequest // keyed by request_uri
}

func (s *Store) ensurePAR() *parState {
	// parMu guards s.par itself (init-once). s.par.mu guards the map.
	s.parInitMu.Lock()
	defer s.parInitMu.Unlock()
	if s.par == nil {
		s.par = &parState{requests: map[string]pushedRequest{}}
	}
	return s.par
}

// InsertPushedRequest implements as.PARStorage.
func (s *Store) InsertPushedRequest(_ context.Context, requestURI string, payload []byte, expiresAt time.Time) error {
	p := s.ensurePAR()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests[requestURI] = pushedRequest{payload: payload, expiresAt: expiresAt}
	return nil
}

// ConsumePushedRequest implements as.PARStorage: atomically fetches and
// deletes, returning ErrNotFound when missing or expired.
func (s *Store) ConsumePushedRequest(_ context.Context, requestURI string) ([]byte, error) {
	p := s.ensurePAR()
	p.mu.Lock()
	defer p.mu.Unlock()
	req, ok := p.requests[requestURI]
	if !ok {
		return nil, storage.ErrNotFound
	}
	delete(p.requests, requestURI)
	if time.Now().After(req.expiresAt) {
		return nil, storage.ErrNotFound
	}
	return req.payload, nil
}
