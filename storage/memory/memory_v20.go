package memory

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

// v2.0 (phase 1 + 2): in-memory OAuth 2.1 authorization server adapter.
// All state lives in a sidecar so the Store{} literal in tests stays small.
// Concurrency: each map is guarded by its own RWMutex; ConsumeAuthorizationCode
// uses a dedicated lock to make the load-and-delete atomic under contention.

type v20State struct {
	mu sync.RWMutex

	clients          map[string]theauth.OAuthClient // keyed by client_id
	clientsByID      map[theauth.ULID]string
	authzCodes       map[string]theauth.AuthorizationCode
	authzCodesMu     sync.Mutex                      // serialises ConsumeAuthorizationCode
	refreshTokens    map[string]theauth.RefreshToken // keyed by hex(hash)
	refreshTokensByF map[theauth.ULID][]string       // family_id -> list of hash keys

	jwksKeys map[string]theauth.JWKSKey

	// v2.0 phase 3 + 4 state. Each map is guarded by the shared mu lock so
	// admin / token / introspect paths see a consistent snapshot.
	agents           map[theauth.ULID]theauth.Agent
	agentsByClientID map[string]theauth.ULID
	agentCredentials map[theauth.ULID]theauth.AgentCredential
	credsByAgent     map[theauth.ULID][]theauth.ULID
	delegations      map[theauth.ULID]theauth.DelegationGrant
	delegByUser      map[theauth.ULID][]theauth.ULID
	delegByAgent     map[theauth.ULID][]theauth.ULID
	delegByTuple     map[string]theauth.ULID // user|agent|resource -> id
}

func (s *Store) ensureV20() *v20State {
	if s.v20 == nil {
		s.v20 = &v20State{
			clients:          map[string]theauth.OAuthClient{},
			clientsByID:      map[theauth.ULID]string{},
			authzCodes:       map[string]theauth.AuthorizationCode{},
			refreshTokens:    map[string]theauth.RefreshToken{},
			refreshTokensByF: map[theauth.ULID][]string{},
			jwksKeys:         map[string]theauth.JWKSKey{},
			agents:           map[theauth.ULID]theauth.Agent{},
			agentsByClientID: map[string]theauth.ULID{},
			agentCredentials: map[theauth.ULID]theauth.AgentCredential{},
			credsByAgent:     map[theauth.ULID][]theauth.ULID{},
			delegations:      map[theauth.ULID]theauth.DelegationGrant{},
			delegByUser:      map[theauth.ULID][]theauth.ULID{},
			delegByAgent:     map[theauth.ULID][]theauth.ULID{},
			delegByTuple:     map[string]theauth.ULID{},
		}
	}
	return s.v20
}

// ---------- OAuth clients ----------

func (s *Store) InsertOAuthClient(_ context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error) {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, dup := v.clients[c.ClientID]; dup {
		return theauth.OAuthClient{}, storage.ErrNotFound
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = c.CreatedAt
	}
	v.clients[c.ClientID] = c
	v.clientsByID[c.ID] = c.ClientID
	return c, nil
}

func (s *Store) OAuthClientByClientID(_ context.Context, clientID string) (*theauth.OAuthClient, error) {
	v := s.ensureV20()
	v.mu.RLock()
	defer v.mu.RUnlock()
	c, ok := v.clients[clientID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := c
	return &cp, nil
}

func (s *Store) UpdateOAuthClient(_ context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error) {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	existing, ok := v.clients[c.ClientID]
	if !ok {
		return theauth.OAuthClient{}, storage.ErrNotFound
	}
	c.CreatedAt = existing.CreatedAt
	c.UpdatedAt = time.Now()
	v.clients[c.ClientID] = c
	return c, nil
}

func (s *Store) DeleteOAuthClient(_ context.Context, clientID string) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.clients[clientID]
	if !ok {
		return storage.ErrNotFound
	}
	delete(v.clients, clientID)
	delete(v.clientsByID, c.ID)
	return nil
}

// ---------- authorization codes ----------

func (s *Store) InsertAuthorizationCode(_ context.Context, c theauth.AuthorizationCode) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	v.authzCodes[c.Code] = c
	return nil
}

// ConsumeAuthorizationCode is atomic per code: the dedicated authzCodesMu
// serialises concurrent load-and-delete calls so exactly one caller succeeds
// per code. Matches the Postgres DELETE ... RETURNING guarantee.
func (s *Store) ConsumeAuthorizationCode(_ context.Context, code string) (*theauth.AuthorizationCode, error) {
	v := s.ensureV20()
	v.authzCodesMu.Lock()
	defer v.authzCodesMu.Unlock()
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.authzCodes[code]
	if !ok {
		return nil, storage.ErrNotFound
	}
	delete(v.authzCodes, code)
	cp := c
	return &cp, nil
}

// ---------- refresh tokens ----------

func (s *Store) InsertRefreshToken(_ context.Context, t theauth.RefreshToken) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	key := bytesHexKey(t.Hash)
	v.refreshTokens[key] = t
	v.refreshTokensByF[t.FamilyID] = append(v.refreshTokensByF[t.FamilyID], key)
	return nil
}

func (s *Store) RefreshTokenByHash(_ context.Context, hash []byte) (*theauth.RefreshToken, error) {
	v := s.ensureV20()
	v.mu.RLock()
	defer v.mu.RUnlock()
	t, ok := v.refreshTokens[bytesHexKey(hash)]
	if !ok {
		// Loop in case of theoretical hash key collision; the map key is
		// hex(hash) so a collision is impossible, but the loop is cheap.
		for _, candidate := range v.refreshTokens {
			if bytes.Equal(candidate.Hash, hash) {
				cp := candidate
				return &cp, nil
			}
		}
		return nil, storage.ErrNotFound
	}
	cp := t
	return &cp, nil
}

func (s *Store) RevokeRefreshToken(_ context.Context, hash []byte, reason string) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	key := bytesHexKey(hash)
	t, ok := v.refreshTokens[key]
	if !ok {
		return storage.ErrNotFound
	}
	now := time.Now()
	t.RevokedAt = &now
	t.RevocationNote = reason
	v.refreshTokens[key] = t
	return nil
}

func (s *Store) RevokeRefreshTokenFamily(_ context.Context, familyID theauth.ULID, reason string) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	keys, ok := v.refreshTokensByF[familyID]
	if !ok {
		return nil
	}
	now := time.Now()
	for _, k := range keys {
		t := v.refreshTokens[k]
		if t.RevokedAt == nil {
			t.RevokedAt = &now
			t.RevocationNote = reason
			v.refreshTokens[k] = t
		}
	}
	return nil
}

// ---------- JWKS keys ----------

func (s *Store) InsertJWKSKey(_ context.Context, k theauth.JWKSKey) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, dup := v.jwksKeys[k.KID]; dup {
		return storage.ErrNotFound
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now()
	}
	v.jwksKeys[k.KID] = k
	return nil
}

func (s *Store) JWKSKeyByKID(_ context.Context, kid string) (*theauth.JWKSKey, error) {
	v := s.ensureV20()
	v.mu.RLock()
	defer v.mu.RUnlock()
	k, ok := v.jwksKeys[kid]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := k
	return &cp, nil
}

func (s *Store) JWKSKeysAll(_ context.Context) ([]theauth.JWKSKey, error) {
	v := s.ensureV20()
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]theauth.JWKSKey, 0, len(v.jwksKeys))
	for _, k := range v.jwksKeys {
		out = append(out, k)
	}
	// Deterministic order so callers iterating the snapshot see stable
	// behavior across runs.
	sort.Slice(out, func(i, j int) bool { return out[i].KID < out[j].KID })
	return out, nil
}

func (s *Store) UpdateJWKSKeyState(_ context.Context, kid, state string, at time.Time) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	k, ok := v.jwksKeys[kid]
	if !ok {
		return storage.ErrNotFound
	}
	k.State = state
	switch state {
	case theauth.JWKSStateCurrent:
		t := at
		k.PromotedAt = &t
	case theauth.JWKSStateRetired:
		t := at
		k.RetiredAt = &t
	}
	v.jwksKeys[kid] = k
	return nil
}

// ---------- agents (v2.0 phase 3) ----------

func (s *Store) InsertAgent(_ context.Context, a theauth.Agent) (theauth.Agent, error) {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, dup := v.agents[a.ID]; dup {
		return theauth.Agent{}, storage.ErrNotFound
	}
	if _, dup := v.agentsByClientID[a.ClientID]; dup {
		return theauth.Agent{}, storage.ErrNotFound
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	if a.Status == "" {
		a.Status = theauth.AgentStatusActive
	}
	v.agents[a.ID] = a
	v.agentsByClientID[a.ClientID] = a.ID
	return a, nil
}

func (s *Store) AgentByID(_ context.Context, id theauth.ULID) (*theauth.Agent, error) {
	v := s.ensureV20()
	v.mu.RLock()
	defer v.mu.RUnlock()
	a, ok := v.agents[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := a
	return &cp, nil
}

func (s *Store) AgentByClientID(_ context.Context, clientID string) (*theauth.Agent, error) {
	v := s.ensureV20()
	v.mu.RLock()
	defer v.mu.RUnlock()
	id, ok := v.agentsByClientID[clientID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	a := v.agents[id]
	return &a, nil
}

func (s *Store) AgentsByOwner(_ context.Context, owner theauth.AgentOwner) ([]theauth.Agent, error) {
	v := s.ensureV20()
	v.mu.RLock()
	defer v.mu.RUnlock()
	var out []theauth.Agent
	for _, a := range v.agents {
		switch {
		case owner.UserID != nil && a.OwnerUserID != nil && *a.OwnerUserID == *owner.UserID:
			out = append(out, a)
		case owner.OrganizationID != nil && a.OrganizationID != nil && *a.OrganizationID == *owner.OrganizationID:
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) UpdateAgentStatus(_ context.Context, id theauth.ULID, status string, _ time.Time) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	a, ok := v.agents[id]
	if !ok {
		return storage.ErrNotFound
	}
	a.Status = status
	v.agents[id] = a
	return nil
}

func (s *Store) UpdateAgentLastActive(_ context.Context, id theauth.ULID, at time.Time) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	a, ok := v.agents[id]
	if !ok {
		return storage.ErrNotFound
	}
	t := at
	a.LastActiveAt = &t
	v.agents[id] = a
	return nil
}

// ---------- agent credentials ----------

func (s *Store) InsertAgentCredential(_ context.Context, c theauth.AgentCredential) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, dup := v.agentCredentials[c.ID]; dup {
		return storage.ErrNotFound
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	v.agentCredentials[c.ID] = c
	v.credsByAgent[c.AgentID] = append(v.credsByAgent[c.AgentID], c.ID)
	return nil
}

func (s *Store) AgentCredentialsByAgentID(_ context.Context, agentID theauth.ULID) ([]theauth.AgentCredential, error) {
	v := s.ensureV20()
	v.mu.RLock()
	defer v.mu.RUnlock()
	ids := v.credsByAgent[agentID]
	out := make([]theauth.AgentCredential, 0, len(ids))
	for _, id := range ids {
		out = append(out, v.agentCredentials[id])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) RevokeAgentCredential(_ context.Context, id theauth.ULID, at time.Time) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.agentCredentials[id]
	if !ok {
		return storage.ErrNotFound
	}
	t := at
	c.RevokedAt = &t
	v.agentCredentials[id] = c
	return nil
}

func (s *Store) UpdateAgentCredentialLastUsed(_ context.Context, id theauth.ULID, at time.Time) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.agentCredentials[id]
	if !ok {
		return storage.ErrNotFound
	}
	t := at
	c.LastUsedAt = &t
	v.agentCredentials[id] = c
	return nil
}

// ---------- delegations (v2.0 phase 4) ----------

func (s *Store) InsertDelegationGrant(_ context.Context, g theauth.DelegationGrant) (theauth.DelegationGrant, error) {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	key := delegationTupleKey(g.UserID, g.AgentID, g.Resource)
	if existingID, dup := v.delegByTuple[key]; dup {
		existing := v.delegations[existingID]
		if existing.RevokedAt == nil {
			return theauth.DelegationGrant{}, storage.ErrNotFound
		}
		// Replace a previously-revoked grant with the fresh one; tuple
		// uniqueness only constrains live rows.
		delete(v.delegByTuple, key)
	}
	if g.CreatedAt.IsZero() {
		g.CreatedAt = time.Now()
	}
	v.delegations[g.ID] = g
	v.delegByTuple[key] = g.ID
	v.delegByUser[g.UserID] = append(v.delegByUser[g.UserID], g.ID)
	v.delegByAgent[g.AgentID] = append(v.delegByAgent[g.AgentID], g.ID)
	return g, nil
}

func (s *Store) DelegationGrantByID(_ context.Context, id theauth.ULID) (*theauth.DelegationGrant, error) {
	v := s.ensureV20()
	v.mu.RLock()
	defer v.mu.RUnlock()
	g, ok := v.delegations[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := g
	return &cp, nil
}

func (s *Store) DelegationGrantByUserAgentResource(_ context.Context, userID, agentID theauth.ULID, resource string) (*theauth.DelegationGrant, error) {
	v := s.ensureV20()
	v.mu.RLock()
	defer v.mu.RUnlock()
	id, ok := v.delegByTuple[delegationTupleKey(userID, agentID, resource)]
	if !ok {
		return nil, storage.ErrNotFound
	}
	g := v.delegations[id]
	return &g, nil
}

func (s *Store) DelegationGrantsByUserID(_ context.Context, userID theauth.ULID) ([]theauth.DelegationGrant, error) {
	v := s.ensureV20()
	v.mu.RLock()
	defer v.mu.RUnlock()
	ids := v.delegByUser[userID]
	out := make([]theauth.DelegationGrant, 0, len(ids))
	for _, id := range ids {
		out = append(out, v.delegations[id])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) DelegationGrantsByAgentID(_ context.Context, agentID theauth.ULID) ([]theauth.DelegationGrant, error) {
	v := s.ensureV20()
	v.mu.RLock()
	defer v.mu.RUnlock()
	ids := v.delegByAgent[agentID]
	out := make([]theauth.DelegationGrant, 0, len(ids))
	for _, id := range ids {
		out = append(out, v.delegations[id])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) RevokeDelegationGrant(_ context.Context, id theauth.ULID, at time.Time, reason string) error {
	v := s.ensureV20()
	v.mu.Lock()
	defer v.mu.Unlock()
	g, ok := v.delegations[id]
	if !ok {
		return storage.ErrNotFound
	}
	t := at
	g.RevokedAt = &t
	g.RevocationNote = reason
	v.delegations[id] = g
	return nil
}

// ---------- helpers ----------

const hexAlphabet = "0123456789abcdef"

func bytesHexKey(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexAlphabet[c>>4]
		out[i*2+1] = hexAlphabet[c&0x0f]
	}
	return string(out)
}

func delegationTupleKey(userID, agentID theauth.ULID, resource string) string {
	return userID.String() + "|" + agentID.String() + "|" + resource
}
