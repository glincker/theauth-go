package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// device_identity_caps.go: registered devices and single-use join tokens over migration 0011.

var _ theauth.DeviceIdentityStorage = (*Store)(nil)

const iotDeviceCols = `id, organization_id, name, spiffe_id, public_key_jwk, key_thumbprint, attestation,
scopes, status, created_at, last_seen_at, revoked_at`

const joinTokenCols = `id, token_hash, token_prefix, organization_id, name, spiffe_id, scopes, created_by,
created_at, expires_at, redeemed_at, device_id, revoked_at, max_uses, uses`

// InsertDevice stores a device, returning ErrDeviceConflict when its SPIFFE ID is taken.
func (s *Store) InsertDevice(ctx context.Context, d theauth.Device) error {
	scopes, err := encodeList(d.Scopes)
	if err != nil {
		return wrap("insert device", err)
	}
	var spiffe sql.NullString
	if d.SPIFFEID != "" {
		spiffe = sql.NullString{String: d.SPIFFEID, Valid: true}
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO theauth_iot_devices (`+iotDeviceCols+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		idStr(d.ID), idPtrStr(d.OrganizationID), d.Name, spiffe, string(d.PublicKeyJWK), d.KeyThumbprint,
		d.Attestation, scopes, d.Status, toMicro(orNow(d.CreatedAt)), toNullMicro(d.LastSeenAt), toNullMicro(d.RevokedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") && strings.Contains(err.Error(), "spiffe_id") {
			return theauth.ErrDeviceConflict
		}
		return wrap("insert device", err)
	}
	return nil
}

func scanIoTDevice(r scanner) (theauth.Device, error) {
	var (
		id, name, jwk, thumb, att, scopes, status string
		org, spiffe                               sql.NullString
		created                                   int64
		lastSeen, revoked                         sql.NullInt64
	)
	if err := r.Scan(&id, &org, &name, &spiffe, &jwk, &thumb, &att, &scopes, &status, &created, &lastSeen, &revoked); err != nil {
		return theauth.Device{}, err
	}
	did, err := parseID(id)
	if err != nil {
		return theauth.Device{}, err
	}
	orgID, err := parseIDPtr(org)
	if err != nil {
		return theauth.Device{}, err
	}
	sc, err := decodeList(scopes)
	if err != nil {
		return theauth.Device{}, err
	}
	return theauth.Device{
		ID: did, OrganizationID: orgID, Name: name, SPIFFEID: spiffe.String, PublicKeyJWK: []byte(jwk),
		KeyThumbprint: thumb, Attestation: att, Scopes: sc, Status: status,
		CreatedAt: fromMicro(created), LastSeenAt: fromNullMicro(lastSeen), RevokedAt: fromNullMicro(revoked),
	}, nil
}

// DeviceByID returns the device, else ErrStorageNotFound.
func (s *Store) DeviceByID(ctx context.Context, id theauth.ULID) (*theauth.Device, error) {
	d, err := scanIoTDevice(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+iotDeviceCols+` FROM theauth_iot_devices WHERE id = ?`), idStr(id)))
	if err != nil {
		return nil, notFoundOr("device by id", err)
	}
	return &d, nil
}

// ListDevices returns devices newest first. A nil orgID lists every device.
func (s *Store) ListDevices(ctx context.Context, orgID *theauth.ULID) ([]theauth.Device, error) {
	q := `SELECT ` + iotDeviceCols + ` FROM theauth_iot_devices`
	var args []any
	if orgID != nil {
		q += ` WHERE organization_id = ?`
		args = append(args, idStr(*orgID))
	}
	rows, err := s.db.QueryContext(ctx, s.q(q+` ORDER BY created_at DESC, id DESC`), args...)
	if err != nil {
		return nil, wrap("list devices", err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.Device{}
	for rows.Next() {
		d, err := scanIoTDevice(rows)
		if err != nil {
			return nil, wrap("list devices", err)
		}
		out = append(out, d)
	}
	return out, wrap("list devices", rows.Err())
}

// RevokeDevice marks an active device revoked and reports whether it changed anything.
func (s *Store) RevokeDevice(ctx context.Context, id theauth.ULID, at time.Time) (bool, error) {
	return s.execApplied(ctx, "revoke device",
		`UPDATE theauth_iot_devices SET status = 'revoked', revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		toMicro(at), idStr(id))
}

// TouchDevice stamps last_seen_at.
func (s *Store) TouchDevice(ctx context.Context, id theauth.ULID, at time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE theauth_iot_devices SET last_seen_at = ? WHERE id = ?`), toMicro(at), idStr(id))
	return wrap("touch device", err)
}

// InsertDeviceJoinToken stores a join token.
func (s *Store) InsertDeviceJoinToken(ctx context.Context, t theauth.DeviceJoinToken) error {
	scopes, err := encodeList(t.Scopes)
	if err != nil {
		return wrap("insert device join token", err)
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO theauth_device_join_tokens (`+joinTokenCols+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		idStr(t.ID), nonNilBytes(t.TokenHash), t.Prefix, idPtrStr(t.OrganizationID), t.Name, t.SPIFFEID, scopes,
		idPtrStr(t.CreatedBy), toMicro(orNow(t.CreatedAt)), toMicro(t.ExpiresAt), toNullMicro(t.RedeemedAt),
		idPtrStr(t.DeviceID), toNullMicro(t.RevokedAt), t.EffectiveMaxUses(), t.Uses)
	return wrap("insert device join token", err)
}

func scanJoinToken(r scanner) (theauth.DeviceJoinToken, error) {
	var (
		id, prefix, name, spiffe, scopes string
		hash                             []byte
		org, by, dev                     sql.NullString
		created, expires                 int64
		redeemed, revoked                sql.NullInt64
		maxUses, uses                    int
	)
	if err := r.Scan(&id, &hash, &prefix, &org, &name, &spiffe, &scopes, &by, &created, &expires, &redeemed, &dev, &revoked, &maxUses, &uses); err != nil {
		return theauth.DeviceJoinToken{}, err
	}
	tid, err := parseID(id)
	if err != nil {
		return theauth.DeviceJoinToken{}, err
	}
	orgID, err := parseIDPtr(org)
	if err != nil {
		return theauth.DeviceJoinToken{}, err
	}
	createdBy, err := parseIDPtr(by)
	if err != nil {
		return theauth.DeviceJoinToken{}, err
	}
	deviceID, err := parseIDPtr(dev)
	if err != nil {
		return theauth.DeviceJoinToken{}, err
	}
	sc, err := decodeList(scopes)
	if err != nil {
		return theauth.DeviceJoinToken{}, err
	}
	return theauth.DeviceJoinToken{
		ID: tid, TokenHash: hash, Prefix: prefix, OrganizationID: orgID, Name: name, SPIFFEID: spiffe, Scopes: sc,
		CreatedBy: createdBy, CreatedAt: fromMicro(created), ExpiresAt: fromMicro(expires),
		RedeemedAt: fromNullMicro(redeemed), DeviceID: deviceID, RevokedAt: fromNullMicro(revoked),
		MaxUses: maxUses, Uses: uses,
	}, nil
}

// DeviceJoinTokenByHash returns the token with the given digest, else ErrStorageNotFound.
func (s *Store) DeviceJoinTokenByHash(ctx context.Context, hash []byte) (*theauth.DeviceJoinToken, error) {
	t, err := scanJoinToken(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+joinTokenCols+` FROM theauth_device_join_tokens WHERE token_hash = ?`), hash))
	if err != nil {
		return nil, notFoundOr("device join token by hash", err)
	}
	return &t, nil
}

// DeviceJoinTokenByID returns the token, else ErrStorageNotFound.
func (s *Store) DeviceJoinTokenByID(ctx context.Context, id theauth.ULID) (*theauth.DeviceJoinToken, error) {
	t, err := scanJoinToken(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+joinTokenCols+` FROM theauth_device_join_tokens WHERE id = ?`), idStr(id)))
	if err != nil {
		return nil, notFoundOr("device join token by id", err)
	}
	return &t, nil
}

// RevokeDeviceJoinToken revokes a token that is not yet revoked.
func (s *Store) RevokeDeviceJoinToken(ctx context.Context, id theauth.ULID, at time.Time) (bool, error) {
	return s.execApplied(ctx, "revoke device join token",
		`UPDATE theauth_device_join_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		toMicro(at), idStr(id))
}

// RedeemDeviceJoinToken spends one use of an unrevoked, unexpired token and reports whether this
// call did it. A single use token (max_uses 1) can be won by exactly one caller.
func (s *Store) RedeemDeviceJoinToken(ctx context.Context, id, deviceID theauth.ULID, now time.Time) (bool, error) {
	return s.execApplied(ctx, "redeem device join token",
		`UPDATE theauth_device_join_tokens SET
redeemed_at = CASE WHEN uses + 1 >= max_uses THEN ? ELSE NULL END,
device_id = CASE WHEN max_uses = 1 THEN ? ELSE NULL END,
uses = uses + 1
WHERE id = ? AND uses < max_uses AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > ?`,
		toMicro(now), idStr(deviceID), idStr(id), toMicro(now))
}

// RefundDeviceJoinToken gives back one use when enrollment failed after it.
func (s *Store) RefundDeviceJoinToken(ctx context.Context, id theauth.ULID) error {
	_, err := s.db.ExecContext(ctx, s.q(
		`UPDATE theauth_device_join_tokens SET redeemed_at = NULL, device_id = NULL, uses = MAX(uses - 1, 0) WHERE id = ?`), idStr(id))
	return wrap("refund device join token", err)
}

// SuspendDevice moves an active device to suspended.
func (s *Store) SuspendDevice(ctx context.Context, id theauth.ULID) (bool, error) {
	return s.setDeviceStatus(ctx, id, "active", "suspended")
}

// ResumeDevice moves a suspended device back to active. A revoked device stays revoked.
func (s *Store) ResumeDevice(ctx context.Context, id theauth.ULID) (bool, error) {
	return s.setDeviceStatus(ctx, id, "suspended", "active")
}

func (s *Store) setDeviceStatus(ctx context.Context, id theauth.ULID, from, to string) (bool, error) {
	return s.execApplied(ctx, "set device status",
		`UPDATE theauth_iot_devices SET status = ? WHERE id = ? AND status = ? AND revoked_at IS NULL`,
		to, idStr(id), from)
}

// DeviceBySPIFFEID returns the device with the SPIFFE ID, else ErrStorageNotFound.
func (s *Store) DeviceBySPIFFEID(ctx context.Context, spiffeID string) (*theauth.Device, error) {
	if spiffeID == "" {
		return nil, theauth.ErrStorageNotFound
	}
	d, err := scanIoTDevice(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+iotDeviceCols+` FROM theauth_iot_devices WHERE spiffe_id = ?`), spiffeID))
	if err != nil {
		return nil, notFoundOr("device by spiffe id", err)
	}
	return &d, nil
}

// DeviceByKeyThumbprint returns the newest device enrolled with the key.
func (s *Store) DeviceByKeyThumbprint(ctx context.Context, thumbprint string) (*theauth.Device, error) {
	if thumbprint == "" {
		return nil, theauth.ErrStorageNotFound
	}
	d, err := scanIoTDevice(s.db.QueryRowContext(ctx, s.q(`SELECT `+iotDeviceCols+
		` FROM theauth_iot_devices WHERE key_thumbprint = ? ORDER BY created_at DESC, id DESC LIMIT 1`), thumbprint))
	if err != nil {
		return nil, notFoundOr("device by key thumbprint", err)
	}
	return &d, nil
}

// execApplied runs a conditional update and reports whether it changed a row.
func (s *Store) execApplied(ctx context.Context, op, query string, args ...any) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(query), args...)
	if err != nil {
		return false, wrap(op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, wrap(op, err)
	}
	return n == 1, nil
}
