package memory

import (
	"bytes"
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

// tokenState is usable as a zero value.
type tokenState struct {
	mu      sync.Mutex
	tokens  map[theauth.ULID]theauth.APIToken
	devices map[theauth.ULID]theauth.DeviceCode
}

func (t *tokenState) init() {
	if t.tokens == nil {
		t.tokens = map[theauth.ULID]theauth.APIToken{}
		t.devices = map[theauth.ULID]theauth.DeviceCode{}
	}
}

func cloneToken(t theauth.APIToken) theauth.APIToken {
	t.Abilities = slices.Clone(t.Abilities)
	t.TokenHash = bytes.Clone(t.TokenHash)
	return t
}

func cloneDevice(d theauth.DeviceCode) theauth.DeviceCode {
	d.RequestedAbilities = slices.Clone(d.RequestedAbilities)
	d.ApprovedAbilities = slices.Clone(d.ApprovedAbilities)
	d.DeviceCodeHash = bytes.Clone(d.DeviceCodeHash)
	return d
}

func sortNewestFirst(out []theauth.APIToken) {
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
}

func (s *Store) InsertAPIToken(_ context.Context, t theauth.APIToken) (theauth.APIToken, error) {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	s.tokens.init()
	s.tokens.tokens[t.ID] = cloneToken(t)
	return cloneToken(t), nil
}

func (s *Store) APITokenByHash(_ context.Context, hash []byte) (*theauth.APIToken, error) {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	for _, t := range s.tokens.tokens {
		if bytes.Equal(t.TokenHash, hash) {
			cp := cloneToken(t)
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) APITokenByID(_ context.Context, id theauth.ULID) (*theauth.APIToken, error) {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	t, ok := s.tokens.tokens[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := cloneToken(t)
	return &cp, nil
}

func (s *Store) APITokensByOwner(_ context.Context, ownerID theauth.ULID) ([]theauth.APIToken, error) {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	out := []theauth.APIToken{}
	for _, t := range s.tokens.tokens {
		if t.OwnerID == ownerID {
			out = append(out, cloneToken(t))
		}
	}
	sortNewestFirst(out)
	return out, nil
}

func (s *Store) ListAPITokens(_ context.Context) ([]theauth.APIToken, error) {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	out := make([]theauth.APIToken, 0, len(s.tokens.tokens))
	for _, t := range s.tokens.tokens {
		out = append(out, cloneToken(t))
	}
	sortNewestFirst(out)
	return out, nil
}

func (s *Store) RevokeAPIToken(_ context.Context, id theauth.ULID, at time.Time) error {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	t, ok := s.tokens.tokens[id]
	if !ok {
		return storage.ErrNotFound
	}
	if t.RevokedAt == nil {
		t.RevokedAt = &at
		s.tokens.tokens[id] = t
	}
	return nil
}

func (s *Store) RevokeAPITokensByOwner(_ context.Context, ownerID theauth.ULID, at time.Time) (int, error) {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	n := 0
	for id, t := range s.tokens.tokens {
		if t.OwnerID == ownerID && t.RevokedAt == nil {
			t.RevokedAt = &at
			s.tokens.tokens[id] = t
			n++
		}
	}
	return n, nil
}

func (s *Store) TouchAPITokenLastUsed(_ context.Context, id theauth.ULID, at time.Time) error {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	t, ok := s.tokens.tokens[id]
	if !ok {
		return storage.ErrNotFound
	}
	t.LastUsedAt = &at
	s.tokens.tokens[id] = t
	return nil
}

func (s *Store) InsertDeviceCode(_ context.Context, d theauth.DeviceCode) error {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	s.tokens.init()
	for _, e := range s.tokens.devices {
		if e.UserCode == d.UserCode {
			return theauth.ErrDeviceUserCodeTaken
		}
	}
	s.tokens.devices[d.ID] = cloneDevice(d)
	return nil
}

func (s *Store) findDevice(match func(theauth.DeviceCode) bool) (theauth.ULID, theauth.DeviceCode, bool) {
	for id, d := range s.tokens.devices {
		if match(d) {
			return id, d, true
		}
	}
	return theauth.ULID{}, theauth.DeviceCode{}, false
}

func (s *Store) DeviceCodeByUserCode(_ context.Context, userCode string) (*theauth.DeviceCode, error) {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	_, d, ok := s.findDevice(func(d theauth.DeviceCode) bool { return d.UserCode == userCode })
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := cloneDevice(d)
	return &cp, nil
}

func (s *Store) DeviceCodeByHash(_ context.Context, hash []byte) (*theauth.DeviceCode, error) {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	_, d, ok := s.findDevice(func(d theauth.DeviceCode) bool { return bytes.Equal(d.DeviceCodeHash, hash) })
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := cloneDevice(d)
	return &cp, nil
}

func (s *Store) DecideDeviceCode(_ context.Context, userCode string, dec theauth.DeviceDecision, now time.Time) error {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	id, d, ok := s.findDevice(func(d theauth.DeviceCode) bool { return d.UserCode == userCode })
	if !ok || d.Status != theauth.DeviceStatusPending || !now.Before(d.ExpiresAt) {
		return storage.ErrNotFound
	}
	approver := dec.ApproverID
	d.ApproverID = &approver
	d.Status = theauth.DeviceStatusDenied
	if dec.Approve {
		d.Status = theauth.DeviceStatusApproved
		d.ApprovedAbilities = slices.Clone(dec.Abilities)
	}
	s.tokens.devices[id] = d
	return nil
}

func (s *Store) ClaimDeviceCode(_ context.Context, hash []byte, now time.Time) (*theauth.DeviceCode, error) {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	id, d, ok := s.findDevice(func(d theauth.DeviceCode) bool { return bytes.Equal(d.DeviceCodeHash, hash) })
	if !ok || d.Status != theauth.DeviceStatusApproved || !now.Before(d.ExpiresAt) {
		return nil, storage.ErrNotFound
	}
	d.Status = theauth.DeviceStatusRedeemed
	s.tokens.devices[id] = d
	cp := cloneDevice(d)
	return &cp, nil
}

func (s *Store) RecordDevicePoll(_ context.Context, hash []byte, at time.Time, intervalSeconds int) error {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	id, d, ok := s.findDevice(func(d theauth.DeviceCode) bool { return bytes.Equal(d.DeviceCodeHash, hash) })
	if !ok {
		return storage.ErrNotFound
	}
	d.LastPolledAt = &at
	d.IntervalSeconds = intervalSeconds
	s.tokens.devices[id] = d
	return nil
}

func (s *Store) DeleteExpiredDeviceCodes(_ context.Context, before time.Time) (int, error) {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	n := 0
	for id, d := range s.tokens.devices {
		if d.ExpiresAt.Before(before) {
			delete(s.tokens.devices, id)
			n++
		}
	}
	return n, nil
}

// ListPendingDeviceCodes returns pending, unexpired requests newest first without device code hashes.
func (s *Store) ListPendingDeviceCodes(_ context.Context, f theauth.DevicePendingFilter) ([]theauth.DeviceCode, error) {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	var out []theauth.DeviceCode
	for _, d := range s.tokens.devices {
		if d.Status == theauth.DeviceStatusPending && f.Now.Before(d.ExpiresAt) {
			cp := cloneDevice(d)
			cp.DeviceCodeHash = nil
			out = append(out, cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}
