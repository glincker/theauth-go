package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// iotdevice.go: DeviceIdentityStorage (registered constrained devices and
// join tokens) over migration 0024.

var _ theauth.DeviceIdentityStorage = (*Store)(nil)

const iotDeviceCols = `id, organization_id, name, spiffe_id, public_key_jwk, key_thumbprint, attestation,
scopes, status, created_at, last_seen_at, revoked_at`

const joinTokenCols = `id, token_hash, token_prefix, organization_id, name, spiffe_id, scopes, created_by,
created_at, expires_at, redeemed_at, device_id, revoked_at`

func (s *Store) InsertDevice(ctx context.Context, d theauth.Device) error {
	scopes, err := encodeList(d.Scopes)
	if err != nil {
		return fmt.Errorf("mysql: insert device: %w", err)
	}
	created := d.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO iot_devices (`+iotDeviceCols+`)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		ulidToBytes(d.ID), ulidPtrToBytes(d.OrganizationID), d.Name, nullStringVal(d.SPIFFEID), string(d.PublicKeyJWK),
		d.KeyThumbprint, d.Attestation, scopes, d.Status, timeUTC(created), timePtrToNull(d.LastSeenAt),
		timePtrToNull(d.RevokedAt))
	if err != nil {
		if isMySQL1062(err) && strings.Contains(err.Error(), "uq_iot_devices_spiffe") {
			return theauth.ErrDeviceConflict
		}
		return fmt.Errorf("mysql: insert device: %w", err)
	}
	return nil
}

func scanIoTDevice(r rowScanner) (theauth.Device, error) {
	var (
		idB, orgB                         []byte
		name, jwk, thumb, att, scopes, st string
		spiffe                            sql.NullString
		created                           time.Time
		lastSeen, revoked                 sql.NullTime
	)
	if err := r.Scan(&idB, &orgB, &name, &spiffe, &jwk, &thumb, &att, &scopes, &st, &created, &lastSeen, &revoked); err != nil {
		return theauth.Device{}, err
	}
	sc, err := decodeList(scopes)
	if err != nil {
		return theauth.Device{}, err
	}
	return theauth.Device{
		ID: bytesToULID(idB), OrganizationID: bytesToULIDPtr(orgB), Name: name, SPIFFEID: spiffe.String,
		PublicKeyJWK: []byte(jwk), KeyThumbprint: thumb, Attestation: att, Scopes: sc, Status: st,
		CreatedAt: created.UTC(), LastSeenAt: nullTimeToPtr(lastSeen), RevokedAt: nullTimeToPtr(revoked),
	}, nil
}

func (s *Store) DeviceByID(ctx context.Context, id theauth.ULID) (*theauth.Device, error) {
	d, err := scanIoTDevice(s.db.QueryRowContext(ctx, `SELECT `+iotDeviceCols+` FROM iot_devices WHERE id = ?`, ulidToBytes(id)))
	if err != nil {
		return nil, notFoundOr("device by id", err)
	}
	return &d, nil
}

func (s *Store) ListDevices(ctx context.Context, orgID *theauth.ULID) ([]theauth.Device, error) {
	q := `SELECT ` + iotDeviceCols + ` FROM iot_devices`
	var args []any
	if orgID != nil {
		q += ` WHERE organization_id = ?`
		args = append(args, ulidToBytes(*orgID))
	}
	q += ` ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("mysql: list devices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.Device
	for rows.Next() {
		d, err := scanIoTDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("mysql: list devices: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) RevokeDevice(ctx context.Context, id theauth.ULID, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE iot_devices SET status = 'revoked', revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		timeUTC(at), ulidToBytes(id))
	return rowsOne(res, err, "revoke device")
}

func (s *Store) TouchDevice(ctx context.Context, id theauth.ULID, at time.Time) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE iot_devices SET last_seen_at = ? WHERE id = ?`, timeUTC(at), ulidToBytes(id)); err != nil {
		return fmt.Errorf("mysql: touch device: %w", err)
	}
	return nil
}

func (s *Store) InsertDeviceJoinToken(ctx context.Context, t theauth.DeviceJoinToken) error {
	scopes, err := encodeList(t.Scopes)
	if err != nil {
		return fmt.Errorf("mysql: insert device join token: %w", err)
	}
	created := t.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO device_join_tokens (`+joinTokenCols+`)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ulidToBytes(t.ID), t.TokenHash, t.Prefix, ulidPtrToBytes(t.OrganizationID), t.Name, t.SPIFFEID, scopes,
		ulidPtrToBytes(t.CreatedBy), timeUTC(created), timeUTC(t.ExpiresAt), timePtrToNull(t.RedeemedAt),
		ulidPtrToBytes(t.DeviceID), timePtrToNull(t.RevokedAt))
	if err != nil {
		return fmt.Errorf("mysql: insert device join token: %w", err)
	}
	return nil
}

func scanJoinToken(r rowScanner) (theauth.DeviceJoinToken, error) {
	var (
		idB, orgB, byB, devB, hash   []byte
		prefix, name, spiffe, scopes string
		created, expires             time.Time
		redeemed, revoked            sql.NullTime
	)
	if err := r.Scan(&idB, &hash, &prefix, &orgB, &name, &spiffe, &scopes, &byB, &created, &expires,
		&redeemed, &devB, &revoked); err != nil {
		return theauth.DeviceJoinToken{}, err
	}
	sc, err := decodeList(scopes)
	if err != nil {
		return theauth.DeviceJoinToken{}, err
	}
	return theauth.DeviceJoinToken{
		ID: bytesToULID(idB), TokenHash: hash, Prefix: prefix, OrganizationID: bytesToULIDPtr(orgB), Name: name,
		SPIFFEID: spiffe, Scopes: sc, CreatedBy: bytesToULIDPtr(byB), CreatedAt: created.UTC(),
		ExpiresAt: expires.UTC(), RedeemedAt: nullTimeToPtr(redeemed), DeviceID: bytesToULIDPtr(devB),
		RevokedAt: nullTimeToPtr(revoked),
	}, nil
}

func (s *Store) DeviceJoinTokenByHash(ctx context.Context, hash []byte) (*theauth.DeviceJoinToken, error) {
	t, err := scanJoinToken(s.db.QueryRowContext(ctx, `SELECT `+joinTokenCols+` FROM device_join_tokens WHERE token_hash = ?`, hash))
	if err != nil {
		return nil, notFoundOr("device join token by hash", err)
	}
	return &t, nil
}

func (s *Store) DeviceJoinTokenByID(ctx context.Context, id theauth.ULID) (*theauth.DeviceJoinToken, error) {
	t, err := scanJoinToken(s.db.QueryRowContext(ctx, `SELECT `+joinTokenCols+` FROM device_join_tokens WHERE id = ?`, ulidToBytes(id)))
	if err != nil {
		return nil, notFoundOr("device join token by id", err)
	}
	return &t, nil
}

func (s *Store) RevokeDeviceJoinToken(ctx context.Context, id theauth.ULID, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE device_join_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, timeUTC(at), ulidToBytes(id))
	return rowsOne(res, err, "revoke device join token")
}

func (s *Store) RedeemDeviceJoinToken(ctx context.Context, id, deviceID theauth.ULID, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE device_join_tokens SET redeemed_at = ?, device_id = ?
WHERE id = ? AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > ?`,
		timeUTC(now), ulidToBytes(deviceID), ulidToBytes(id), timeUTC(now))
	return rowsOne(res, err, "redeem device join token")
}

func (s *Store) RefundDeviceJoinToken(ctx context.Context, id theauth.ULID) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE device_join_tokens SET redeemed_at = NULL, device_id = NULL WHERE id = ?`, ulidToBytes(id)); err != nil {
		return fmt.Errorf("mysql: refund device join token: %w", err)
	}
	return nil
}
