package memory

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// memory_iotdevice.go: in-memory DeviceIdentityStorage (registered devices
// and join tokens). State sits in a sidecar with its own mutex.

type iotDeviceState struct {
	mu      sync.Mutex
	devices map[theauth.ULID]theauth.Device
	tokens  map[theauth.ULID]theauth.DeviceJoinToken
}

func (d *iotDeviceState) init() {
	if d.devices == nil {
		d.devices = map[theauth.ULID]theauth.Device{}
		d.tokens = map[theauth.ULID]theauth.DeviceJoinToken{}
	}
}

func cloneIoTDevice(d theauth.Device) theauth.Device {
	d.PublicKeyJWK = append([]byte(nil), d.PublicKeyJWK...)
	d.Scopes = append([]string(nil), d.Scopes...)
	return d
}

func cloneDeviceJoinToken(t theauth.DeviceJoinToken) theauth.DeviceJoinToken {
	t.TokenHash = append([]byte(nil), t.TokenHash...)
	t.Scopes = append([]string(nil), t.Scopes...)
	return t
}

func (s *Store) InsertDevice(_ context.Context, d theauth.Device) error {
	st := &s.iotdev
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	if d.SPIFFEID != "" {
		for _, o := range st.devices {
			if o.SPIFFEID == d.SPIFFEID {
				return theauth.ErrDeviceConflict
			}
		}
	}
	st.devices[d.ID] = cloneIoTDevice(d)
	return nil
}

func (s *Store) DeviceByID(_ context.Context, id theauth.ULID) (*theauth.Device, error) {
	st := &s.iotdev
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	d, ok := st.devices[id]
	if !ok {
		return nil, theauth.ErrStorageNotFound
	}
	cp := cloneIoTDevice(d)
	return &cp, nil
}

func (s *Store) ListDevices(_ context.Context, orgID *theauth.ULID) ([]theauth.Device, error) {
	st := &s.iotdev
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	var out []theauth.Device
	for _, d := range st.devices {
		if orgID != nil && (d.OrganizationID == nil || *d.OrganizationID != *orgID) {
			continue
		}
		out = append(out, cloneIoTDevice(d))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return bytes.Compare(out[i].ID[:], out[j].ID[:]) > 0
	})
	return out, nil
}

func (s *Store) RevokeDevice(_ context.Context, id theauth.ULID, at time.Time) (bool, error) {
	st := &s.iotdev
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	d, ok := st.devices[id]
	if !ok || d.RevokedAt != nil {
		return false, nil
	}
	d.Status = theauth.DeviceStatusRevoked
	d.RevokedAt = &at
	st.devices[id] = d
	return true, nil
}

func (s *Store) TouchDevice(_ context.Context, id theauth.ULID, at time.Time) error {
	st := &s.iotdev
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	if d, ok := st.devices[id]; ok {
		d.LastSeenAt = &at
		st.devices[id] = d
	}
	return nil
}

func (s *Store) InsertDeviceJoinToken(_ context.Context, t theauth.DeviceJoinToken) error {
	st := &s.iotdev
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	st.tokens[t.ID] = cloneDeviceJoinToken(t)
	return nil
}

func (s *Store) DeviceJoinTokenByHash(_ context.Context, hash []byte) (*theauth.DeviceJoinToken, error) {
	st := &s.iotdev
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	for _, t := range st.tokens {
		if bytes.Equal(t.TokenHash, hash) {
			cp := cloneDeviceJoinToken(t)
			return &cp, nil
		}
	}
	return nil, theauth.ErrStorageNotFound
}

func (s *Store) DeviceJoinTokenByID(_ context.Context, id theauth.ULID) (*theauth.DeviceJoinToken, error) {
	st := &s.iotdev
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	t, ok := st.tokens[id]
	if !ok {
		return nil, theauth.ErrStorageNotFound
	}
	cp := cloneDeviceJoinToken(t)
	return &cp, nil
}

func (s *Store) RevokeDeviceJoinToken(_ context.Context, id theauth.ULID, at time.Time) (bool, error) {
	st := &s.iotdev
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	t, ok := st.tokens[id]
	if !ok || t.RevokedAt != nil {
		return false, nil
	}
	t.RevokedAt = &at
	st.tokens[id] = t
	return true, nil
}

func (s *Store) RedeemDeviceJoinToken(_ context.Context, id, deviceID theauth.ULID, now time.Time) (bool, error) {
	st := &s.iotdev
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	t, ok := st.tokens[id]
	if !ok || !t.Active(now) {
		return false, nil
	}
	t.RedeemedAt = &now
	t.DeviceID = &deviceID
	st.tokens[id] = t
	return true, nil
}

func (s *Store) RefundDeviceJoinToken(_ context.Context, id theauth.ULID) error {
	st := &s.iotdev
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	if t, ok := st.tokens[id]; ok {
		t.RedeemedAt = nil
		t.DeviceID = nil
		st.tokens[id] = t
	}
	return nil
}
