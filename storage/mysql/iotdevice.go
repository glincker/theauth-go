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
attestation_claims, app_attest_counter, scopes, status, created_at, last_seen_at, revoked_at`

const joinTokenCols = `id, token_hash, token_prefix, organization_id, name, spiffe_id, scopes, created_by,
created_at, expires_at, redeemed_at, device_id, revoked_at, max_uses, uses`

func (s *Store) InsertDevice(ctx context.Context, d theauth.Device) error {
	scopes, err := encodeList(d.Scopes)
	if err != nil {
		return fmt.Errorf("mysql: insert device: %w", err)
	}
	created := d.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	claims, err := encodeAttestationClaims(d.AttestationClaims)
	if err != nil {
		return fmt.Errorf("mysql: insert device: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO iot_devices (`+iotDeviceCols+`)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ulidToBytes(d.ID), ulidPtrToBytes(d.OrganizationID), d.Name, nullStringVal(d.SPIFFEID), string(d.PublicKeyJWK),
		d.KeyThumbprint, d.Attestation, nullStringVal(claims), uint64(d.AppAttestCounter), scopes, d.Status, timeUTC(created), timePtrToNull(d.LastSeenAt),
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
		spiffe, claims                    sql.NullString
		created                           time.Time
		counter                           uint64
		lastSeen, revoked                 sql.NullTime
	)
	if err := r.Scan(&idB, &orgB, &name, &spiffe, &jwk, &thumb, &att, &claims, &counter, &scopes, &st, &created, &lastSeen, &revoked); err != nil {
		return theauth.Device{}, err
	}
	sc, err := decodeList(scopes)
	if err != nil {
		return theauth.Device{}, err
	}
	ac, err := decodeAttestationClaims(claims.String)
	if err != nil {
		return theauth.Device{}, err
	}
	return theauth.Device{
		AttestationClaims: ac, AppAttestCounter: uint32(counter),
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

// AdvanceAppAttestCounter raises the App Attest counter in one conditional UPDATE.
func (s *Store) AdvanceAppAttestCounter(ctx context.Context, id theauth.ULID, counter uint32) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE iot_devices SET app_attest_counter = ? WHERE id = ? AND app_attest_counter < ?`,
		uint64(counter), ulidToBytes(id), uint64(counter))
	return rowsOne(res, err, "advance app attest counter")
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
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ulidToBytes(t.ID), t.TokenHash, t.Prefix, ulidPtrToBytes(t.OrganizationID), t.Name, t.SPIFFEID, scopes,
		ulidPtrToBytes(t.CreatedBy), timeUTC(created), timeUTC(t.ExpiresAt), timePtrToNull(t.RedeemedAt),
		ulidPtrToBytes(t.DeviceID), timePtrToNull(t.RevokedAt), t.EffectiveMaxUses(), t.Uses)
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
		maxUses, uses                int
	)
	if err := r.Scan(&idB, &hash, &prefix, &orgB, &name, &spiffe, &scopes, &byB, &created, &expires,
		&redeemed, &devB, &revoked, &maxUses, &uses); err != nil {
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
		RevokedAt: nullTimeToPtr(revoked), MaxUses: maxUses, Uses: uses,
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

// RedeemDeviceJoinToken spends one use. MySQL evaluates SET assignments left to right and later
// ones see the updated value, so redeemed_at and device_id come before the uses increment.
func (s *Store) RedeemDeviceJoinToken(ctx context.Context, id, deviceID theauth.ULID, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE device_join_tokens SET
redeemed_at = CASE WHEN uses + 1 >= max_uses THEN ? ELSE NULL END,
device_id = CASE WHEN max_uses = 1 THEN ? ELSE NULL END,
uses = uses + 1
WHERE id = ? AND uses < max_uses AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > ?`,
		timeUTC(now), ulidToBytes(deviceID), ulidToBytes(id), timeUTC(now))
	return rowsOne(res, err, "redeem device join token")
}

func (s *Store) RefundDeviceJoinToken(ctx context.Context, id theauth.ULID) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE device_join_tokens SET redeemed_at = NULL, device_id = NULL, uses = GREATEST(uses - 1, 0) WHERE id = ?`,
		ulidToBytes(id)); err != nil {
		return fmt.Errorf("mysql: refund device join token: %w", err)
	}
	return nil
}

func (s *Store) SuspendDevice(ctx context.Context, id theauth.ULID) (bool, error) {
	return s.setDeviceStatus(ctx, id, "active", "suspended")
}

func (s *Store) ResumeDevice(ctx context.Context, id theauth.ULID) (bool, error) {
	return s.setDeviceStatus(ctx, id, "suspended", "active")
}

func (s *Store) setDeviceStatus(ctx context.Context, id theauth.ULID, from, to string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE iot_devices SET status = ? WHERE id = ? AND status = ? AND revoked_at IS NULL`,
		to, ulidToBytes(id), from)
	return rowsOne(res, err, "set device status")
}

func (s *Store) DeviceBySPIFFEID(ctx context.Context, spiffeID string) (*theauth.Device, error) {
	if spiffeID == "" {
		return nil, theauth.ErrStorageNotFound
	}
	d, err := scanIoTDevice(s.db.QueryRowContext(ctx, `SELECT `+iotDeviceCols+` FROM iot_devices WHERE spiffe_id = ?`, spiffeID))
	if err != nil {
		return nil, notFoundOr("device by spiffe id", err)
	}
	return &d, nil
}

func (s *Store) DeviceByKeyThumbprint(ctx context.Context, thumbprint string) (*theauth.Device, error) {
	if thumbprint == "" {
		return nil, theauth.ErrStorageNotFound
	}
	d, err := scanIoTDevice(s.db.QueryRowContext(ctx, `SELECT `+iotDeviceCols+
		` FROM iot_devices WHERE key_thumbprint = ? ORDER BY created_at DESC, id DESC LIMIT 1`, thumbprint))
	if err != nil {
		return nil, notFoundOr("device by key thumbprint", err)
	}
	return &d, nil
}
