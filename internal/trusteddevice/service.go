// Package trusteddevice implements remember-this-device records that let a
// password sign-in skip the TOTP prompt for a configurable window.
//
// The browser holds a cookie of the form token.mac. The token is random and
// only its SHA-256 is stored; the mac is an HMAC keyed from the configured
// encryption key so a forged or truncated cookie is rejected before any
// storage lookup. Records are bound to one user, expire, and are revoked
// when the password changes.
package trusteddevice

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/session"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// DefaultTTL is how long a device stays trusted when no TTL is configured.
const DefaultTTL = 30 * 24 * time.Hour

// DefaultCookieName is the cookie that carries the device token.
const DefaultCookieName = "theauth_trusted_device"

// Store is the persistence subset this package needs.
type Store interface {
	InsertTrustedDevice(ctx context.Context, d models.TrustedDevice) error
	TrustedDeviceByTokenHash(ctx context.Context, userID models.ULID, hash []byte) (*models.TrustedDevice, error)
	ListTrustedDevices(ctx context.Context, userID models.ULID) ([]models.TrustedDevice, error)
	TouchTrustedDevice(ctx context.Context, id models.ULID, at time.Time) error
	RevokeTrustedDevice(ctx context.Context, userID, id models.ULID) error
	RevokeUserTrustedDevices(ctx context.Context, userID models.ULID) (int, error)
}

// Service issues and checks trusted-device cookies.
type Service struct {
	store Store
	key   []byte
	ttl   time.Duration
	now   func() time.Time
}

// New returns a Service. key must not be empty; ttl <= 0 selects DefaultTTL.
func New(store Store, key []byte, ttl time.Duration) (*Service, error) {
	if store == nil {
		return nil, errors.New("theauth: trusted devices need a store")
	}
	if len(key) == 0 {
		return nil, errors.New("theauth: trusted devices need a signing key")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Service{store: store, key: append([]byte(nil), key...), ttl: ttl, now: time.Now}, nil
}

// TTL returns the trust window.
func (s *Service) TTL() time.Duration { return s.ttl }

func (s *Service) mac(token string) string {
	m := hmac.New(sha256.New, s.key)
	_, _ = m.Write([]byte("theauth/trusted-device/v1:" + token))
	return hex.EncodeToString(m.Sum(nil))
}

// token extracts the token from a cookie value, verifying its mac.
func (s *Service) token(cookie string) (string, bool) {
	i := strings.LastIndexByte(cookie, '.')
	if i <= 0 || i == len(cookie)-1 {
		return "", false
	}
	tok, got := cookie[:i], cookie[i+1:]
	if !hmac.Equal([]byte(got), []byte(s.mac(tok))) {
		return "", false
	}
	return tok, true
}

// Remember stores a new trusted device for userID and returns the cookie
// value and its expiry.
func (s *Service) Remember(ctx context.Context, userID models.ULID, userAgent, ip string) (string, time.Time, error) {
	tok, err := crypto.NewToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now()
	d := models.TrustedDevice{
		ID: ulid.New(), UserID: userID, TokenHash: crypto.HashToken(tok),
		Label: session.DeviceLabel(userAgent), UserAgent: userAgent, IP: ip,
		CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(s.ttl),
	}
	if err := s.store.InsertTrustedDevice(ctx, d); err != nil {
		return "", time.Time{}, fmt.Errorf("theauth: remember device: %w", err)
	}
	return tok + "." + s.mac(tok), d.ExpiresAt, nil
}

// Trusted reports whether cookie is a live trusted device of userID. Any
// lookup error means "not trusted", so the TOTP prompt is shown.
func (s *Service) Trusted(ctx context.Context, userID models.ULID, cookie string) bool {
	tok, ok := s.token(cookie)
	if !ok {
		return false
	}
	d, err := s.store.TrustedDeviceByTokenHash(ctx, userID, crypto.HashToken(tok))
	if err != nil {
		if !errors.Is(err, models.ErrStorageNotFound) {
			slog.Warn("theauth: trusted device lookup failed", "user_id", userID.String(), "err", err.Error())
		}
		return false
	}
	now := s.now()
	if d.RevokedAt != nil || !d.ExpiresAt.After(now) {
		return false
	}
	if err := s.store.TouchTrustedDevice(ctx, d.ID, now); err != nil {
		slog.Warn("theauth: trusted device touch failed", "device_id", d.ID.String(), "err", err.Error())
	}
	return true
}

// List returns the user's live trusted devices, newest first.
func (s *Service) List(ctx context.Context, userID models.ULID) ([]models.TrustedDevice, error) {
	return s.store.ListTrustedDevices(ctx, userID)
}

// Revoke revokes one device owned by userID.
func (s *Service) Revoke(ctx context.Context, userID, id models.ULID) error {
	return s.store.RevokeTrustedDevice(ctx, userID, id)
}

// RevokeAll revokes every device of userID and returns how many it revoked.
func (s *Service) RevokeAll(ctx context.Context, userID models.ULID) (int, error) {
	return s.store.RevokeUserTrustedDevices(ctx, userID)
}
