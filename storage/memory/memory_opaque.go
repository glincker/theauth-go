package memory

import (
	"context"
	"encoding/hex"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// memory_opaque.go: in-memory OpaqueTokenStorage. Expired records are dropped
// opportunistically on insert so the map does not grow without bound.

type opaqueState struct {
	mu     sync.Mutex
	tokens map[string]theauth.OpaqueAccessToken
}

func cloneOpaque(t theauth.OpaqueAccessToken) theauth.OpaqueAccessToken {
	t.Hash = append([]byte(nil), t.Hash...)
	t.Claims = append([]byte(nil), t.Claims...)
	if t.RevokedAt != nil {
		at := *t.RevokedAt
		t.RevokedAt = &at
	}
	return t
}

// InsertOpaqueAccessToken satisfies OpaqueTokenStorage.
func (s *Store) InsertOpaqueAccessToken(_ context.Context, t theauth.OpaqueAccessToken) error {
	st := &s.opaque
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.tokens == nil {
		st.tokens = map[string]theauth.OpaqueAccessToken{}
	}
	now := time.Now()
	for k, v := range st.tokens {
		if v.ExpiresAt.Before(now.Add(-time.Hour)) {
			delete(st.tokens, k)
		}
	}
	st.tokens[hex.EncodeToString(t.Hash)] = cloneOpaque(t)
	return nil
}

// OpaqueAccessTokenByHash satisfies OpaqueTokenStorage.
func (s *Store) OpaqueAccessTokenByHash(_ context.Context, hash []byte) (*theauth.OpaqueAccessToken, error) {
	st := &s.opaque
	st.mu.Lock()
	defer st.mu.Unlock()
	t, ok := st.tokens[hex.EncodeToString(hash)]
	if !ok {
		return nil, theauth.ErrStorageNotFound
	}
	out := cloneOpaque(t)
	return &out, nil
}

// RevokeOpaqueAccessToken satisfies OpaqueTokenStorage.
func (s *Store) RevokeOpaqueAccessToken(_ context.Context, hash []byte) error {
	st := &s.opaque
	st.mu.Lock()
	defer st.mu.Unlock()
	key := hex.EncodeToString(hash)
	t, ok := st.tokens[key]
	if !ok || t.RevokedAt != nil {
		return nil
	}
	now := time.Now()
	t.RevokedAt = &now
	st.tokens[key] = t
	return nil
}
