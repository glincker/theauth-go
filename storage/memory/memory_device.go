package memory

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// memory_device.go: in-memory DeviceAuthorizationStorage (RFC 8628 device
// grant) and RegistrationTokenStorage (initial access tokens). State sits in a
// sidecar with its own mutex so these paths never contend with the core store.

type devAuthState struct {
	mu      sync.Mutex
	devices map[theauth.ULID]theauth.DeviceAuthorization
	regs    map[theauth.ULID]theauth.RegistrationToken
}

func (d *devAuthState) init() {
	if d.devices == nil {
		d.devices = map[theauth.ULID]theauth.DeviceAuthorization{}
		d.regs = map[theauth.ULID]theauth.RegistrationToken{}
	}
}

func cloneDevAuth(d theauth.DeviceAuthorization) theauth.DeviceAuthorization {
	d.DeviceCodeHash = append([]byte(nil), d.DeviceCodeHash...)
	d.UserCodeHash = append([]byte(nil), d.UserCodeHash...)
	d.Scope = append([]string(nil), d.Scope...)
	return d
}

// InsertDeviceAuthorization satisfies DeviceAuthorizationStorage.
func (s *Store) InsertDeviceAuthorization(_ context.Context, in theauth.DeviceAuthorization) error {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	now := time.Now()
	for id, d := range st.devices {
		if bytes.Equal(d.UserCodeHash, in.UserCodeHash) && now.Before(d.ExpiresAt) {
			return theauth.ErrDeviceAuthUserCodeTaken
		}
		// Opportunistic cleanup of long-dead rows keeps the map bounded.
		if now.After(d.ExpiresAt.Add(time.Hour)) {
			delete(st.devices, id)
		}
	}
	st.devices[in.ID] = cloneDevAuth(in)
	return nil
}

func (s *Store) deviceBy(match func(theauth.DeviceAuthorization) bool) (*theauth.DeviceAuthorization, error) {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	for _, d := range st.devices {
		if match(d) {
			cp := cloneDevAuth(d)
			return &cp, nil
		}
	}
	return nil, theauth.ErrStorageNotFound
}

// DeviceAuthorizationByDeviceCodeHash satisfies DeviceAuthorizationStorage.
func (s *Store) DeviceAuthorizationByDeviceCodeHash(_ context.Context, hash []byte) (*theauth.DeviceAuthorization, error) {
	return s.deviceBy(func(d theauth.DeviceAuthorization) bool { return bytes.Equal(d.DeviceCodeHash, hash) })
}

// DeviceAuthorizationByUserCodeHash satisfies DeviceAuthorizationStorage. When
// an expired and a live record share a hash the live one wins.
func (s *Store) DeviceAuthorizationByUserCodeHash(_ context.Context, hash []byte) (*theauth.DeviceAuthorization, error) {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	var best *theauth.DeviceAuthorization
	for _, d := range st.devices {
		if !bytes.Equal(d.UserCodeHash, hash) {
			continue
		}
		if best == nil || d.ExpiresAt.After(best.ExpiresAt) {
			cp := cloneDevAuth(d)
			best = &cp
		}
	}
	if best == nil {
		return nil, theauth.ErrStorageNotFound
	}
	return best, nil
}

// DecideDeviceAuthorization satisfies DeviceAuthorizationStorage.
func (s *Store) DecideDeviceAuthorization(_ context.Context, id theauth.ULID, status string, userID theauth.ULID, now time.Time) (bool, error) {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	d, ok := st.devices[id]
	if !ok || d.Status != theauth.DeviceAuthPending || !now.Before(d.ExpiresAt) {
		return false, nil
	}
	uid, at := userID, now
	d.Status, d.UserID, d.DecidedAt = status, &uid, &at
	st.devices[id] = d
	return true, nil
}

// RecordDeviceAuthorizationPoll satisfies DeviceAuthorizationStorage.
func (s *Store) RecordDeviceAuthorizationPoll(_ context.Context, id theauth.ULID, polledAt time.Time, intervalSeconds int) error {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	d, ok := st.devices[id]
	if !ok {
		return theauth.ErrStorageNotFound
	}
	at := polledAt
	d.LastPollAt, d.IntervalSeconds = &at, intervalSeconds
	st.devices[id] = d
	return nil
}

// ConsumeDeviceAuthorization satisfies DeviceAuthorizationStorage.
func (s *Store) ConsumeDeviceAuthorization(_ context.Context, id theauth.ULID, now time.Time) (bool, error) {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	d, ok := st.devices[id]
	if !ok || d.Status != theauth.DeviceAuthApproved || !now.Before(d.ExpiresAt) {
		return false, nil
	}
	d.Status = theauth.DeviceAuthConsumed
	st.devices[id] = d
	return true, nil
}

// DeleteExpiredDeviceAuthorizations satisfies DeviceAuthorizationStorage.
func (s *Store) DeleteExpiredDeviceAuthorizations(_ context.Context, before time.Time) (int64, error) {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	var n int64
	for id, d := range st.devices {
		if d.ExpiresAt.Before(before) {
			delete(st.devices, id)
			n++
		}
	}
	return n, nil
}

func cloneReg(t theauth.RegistrationToken) theauth.RegistrationToken {
	t.TokenHash = append([]byte(nil), t.TokenHash...)
	t.Scopes = append([]string(nil), t.Scopes...)
	t.GrantTypes = append([]string(nil), t.GrantTypes...)
	return t
}

// InsertRegistrationToken satisfies RegistrationTokenStorage.
func (s *Store) InsertRegistrationToken(_ context.Context, t theauth.RegistrationToken) error {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	st.regs[t.ID] = cloneReg(t)
	return nil
}

// RegistrationTokenByHash satisfies RegistrationTokenStorage.
func (s *Store) RegistrationTokenByHash(_ context.Context, hash []byte) (*theauth.RegistrationToken, error) {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	for _, t := range st.regs {
		if bytes.Equal(t.TokenHash, hash) {
			cp := cloneReg(t)
			return &cp, nil
		}
	}
	return nil, theauth.ErrStorageNotFound
}

// RegistrationTokenByID satisfies RegistrationTokenStorage.
func (s *Store) RegistrationTokenByID(_ context.Context, id theauth.ULID) (*theauth.RegistrationToken, error) {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	t, ok := st.regs[id]
	if !ok {
		return nil, theauth.ErrStorageNotFound
	}
	cp := cloneReg(t)
	return &cp, nil
}

// ListRegistrationTokens satisfies RegistrationTokenStorage.
func (s *Store) ListRegistrationTokens(_ context.Context, orgID *theauth.ULID) ([]theauth.RegistrationToken, error) {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	out := make([]theauth.RegistrationToken, 0, len(st.regs))
	for _, t := range st.regs {
		if orgID != nil && (t.OrganizationID == nil || *t.OrganizationID != *orgID) {
			continue
		}
		out = append(out, cloneReg(t))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return bytes.Compare(out[i].ID[:], out[j].ID[:]) > 0
	})
	return out, nil
}

// RevokeRegistrationToken satisfies RegistrationTokenStorage.
func (s *Store) RevokeRegistrationToken(_ context.Context, id theauth.ULID, at time.Time) (bool, error) {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	t, ok := st.regs[id]
	if !ok || t.RevokedAt != nil {
		return false, nil
	}
	a := at
	t.RevokedAt = &a
	st.regs[id] = t
	return true, nil
}

// RedeemRegistrationToken satisfies RegistrationTokenStorage.
func (s *Store) RedeemRegistrationToken(_ context.Context, id theauth.ULID, now time.Time) (bool, error) {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	t, ok := st.regs[id]
	if !ok || !t.Active(now) {
		return false, nil
	}
	t.Uses++
	n := now
	t.LastUsedAt = &n
	st.regs[id] = t
	return true, nil
}

// RefundRegistrationToken satisfies RegistrationTokenStorage.
func (s *Store) RefundRegistrationToken(_ context.Context, id theauth.ULID) error {
	st := &s.devauth
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	if t, ok := st.regs[id]; ok && t.Uses > 0 {
		t.Uses--
		st.regs[id] = t
	}
	return nil
}
