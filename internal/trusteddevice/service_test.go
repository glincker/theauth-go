package trusteddevice

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// fakeStore is an in-memory Store; the memory adapter cannot be imported
// here because it imports the root package, which imports this one.
type fakeStore struct {
	rows map[models.ULID]models.TrustedDevice
}

func (f *fakeStore) InsertTrustedDevice(_ context.Context, d models.TrustedDevice) error {
	f.rows[d.ID] = d
	return nil
}

func (f *fakeStore) TrustedDeviceByTokenHash(_ context.Context, u models.ULID, h []byte) (*models.TrustedDevice, error) {
	for _, d := range f.rows {
		if d.UserID == u && string(d.TokenHash) == string(h) {
			cp := d
			return &cp, nil
		}
	}
	return nil, models.ErrStorageNotFound
}

func (f *fakeStore) ListTrustedDevices(_ context.Context, u models.ULID) ([]models.TrustedDevice, error) {
	var out []models.TrustedDevice
	for _, d := range f.rows {
		if d.UserID == u && d.RevokedAt == nil && d.ExpiresAt.After(time.Now()) {
			out = append(out, d)
		}
	}
	return out, nil
}

func (f *fakeStore) TouchTrustedDevice(_ context.Context, id models.ULID, at time.Time) error {
	d, ok := f.rows[id]
	if !ok {
		return models.ErrStorageNotFound
	}
	d.LastUsedAt = at
	f.rows[id] = d
	return nil
}

func (f *fakeStore) RevokeTrustedDevice(_ context.Context, u, id models.ULID) error {
	d, ok := f.rows[id]
	if !ok || d.UserID != u || d.RevokedAt != nil {
		return models.ErrStorageNotFound
	}
	now := time.Now()
	d.RevokedAt = &now
	f.rows[id] = d
	return nil
}

func (f *fakeStore) RevokeUserTrustedDevices(_ context.Context, u models.ULID) (int, error) {
	n := 0
	now := time.Now()
	for id, d := range f.rows {
		if d.UserID == u && d.RevokedAt == nil {
			d.RevokedAt = &now
			f.rows[id] = d
			n++
		}
	}
	return n, nil
}

func newSvc(t *testing.T, ttl time.Duration) (*Service, *fakeStore, models.ULID) {
	t.Helper()
	store := &fakeStore{rows: map[models.ULID]models.TrustedDevice{}}
	svc, err := New(store, []byte("0123456789abcdef0123456789abcdef"), ttl)
	if err != nil {
		t.Fatal(err)
	}
	return svc, store, ulid.New()
}

func TestRememberAndTrust(t *testing.T) {
	ctx := context.Background()
	svc, store, uid := newSvc(t, time.Hour)
	cookie, exp, err := svc.Remember(ctx, uid, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0", "203.0.113.4")
	if err != nil {
		t.Fatal(err)
	}
	if !exp.After(time.Now()) {
		t.Fatalf("expiry %v is not in the future", exp)
	}
	if !svc.Trusted(ctx, uid, cookie) {
		t.Fatal("fresh device must be trusted")
	}
	tok := cookie[:strings.LastIndexByte(cookie, '.')]
	if rows, _ := store.ListTrustedDevices(ctx, uid); len(rows) != 1 || string(rows[0].TokenHash) == tok {
		t.Fatalf("token must be stored hashed, rows = %+v", rows)
	}

	other := ulid.New()
	cases := []struct {
		name   string
		user   models.ULID
		cookie string
	}{
		{"other user", other, cookie},
		{"forged mac", uid, tok + ".deadbeef"},
		{"no mac", uid, tok},
		{"empty", uid, ""},
		{"unknown token", uid, "zzz." + svc.mac("zzz")},
	}
	for _, tc := range cases {
		if svc.Trusted(ctx, tc.user, tc.cookie) {
			t.Errorf("%s must not be trusted", tc.name)
		}
	}
}

func TestExpiryAndRevocation(t *testing.T) {
	ctx := context.Background()
	svc, _, uid := newSvc(t, time.Hour)
	cookie, _, err := svc.Remember(ctx, uid, "ua", "ip")
	if err != nil {
		t.Fatal(err)
	}
	svc.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if svc.Trusted(ctx, uid, cookie) {
		t.Fatal("expired device must not be trusted")
	}
	svc.now = time.Now

	if !svc.Trusted(ctx, uid, cookie) {
		t.Fatal("device must be trusted again before revocation")
	}
	n, err := svc.RevokeAll(ctx, uid)
	if err != nil || n != 1 {
		t.Fatalf("RevokeAll = %d, %v", n, err)
	}
	if svc.Trusted(ctx, uid, cookie) {
		t.Fatal("revoked device must not be trusted")
	}
	rows, _ := svc.List(ctx, uid)
	if len(rows) != 0 {
		t.Fatalf("List after revoke = %+v", rows)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(nil, []byte("k"), 0); err == nil {
		t.Error("nil store must fail")
	}
	if _, err := New(&fakeStore{}, nil, 0); err == nil {
		t.Error("empty key must fail")
	}
	svc, err := New(&fakeStore{}, []byte("k"), 0)
	if err != nil || svc.TTL() != DefaultTTL {
		t.Errorf("default ttl = %v, %v", svc.TTL(), err)
	}
}
