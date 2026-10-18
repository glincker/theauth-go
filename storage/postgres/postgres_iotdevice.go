package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// postgres_iotdevice.go: DeviceIdentityStorage (registered constrained
// devices and join tokens) over migration 0024.

var _ theauth.DeviceIdentityStorage = (*Store)(nil)

const iotDeviceCols = `id, organization_id, name, spiffe_id, public_key_jwk, key_thumbprint, attestation,
scopes, status, created_at, last_seen_at, revoked_at`

const joinTokenCols = `id, token_hash, token_prefix, organization_id, name, spiffe_id, scopes, created_by,
created_at, expires_at, redeemed_at, device_id, revoked_at, max_uses, uses`

func (s *Store) InsertDevice(ctx context.Context, d theauth.Device) error {
	scopes, err := encodeList(d.Scopes)
	if err != nil {
		return fmt.Errorf("postgres: insert device: %w", err)
	}
	var spiffe *string
	if d.SPIFFEID != "" {
		spiffe = &d.SPIFFEID
	}
	created := d.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO iot_devices (`+iotDeviceCols+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		ulidToPgUUID(d.ID), uuidPtr(d.OrganizationID), d.Name, spiffe, string(d.PublicKeyJWK), d.KeyThumbprint,
		d.Attestation, scopes, d.Status, created, timePtrToTs(d.LastSeenAt), timePtrToTs(d.RevokedAt))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "iot_devices_spiffe_uq" {
			return theauth.ErrDeviceConflict
		}
		return fmt.Errorf("postgres: insert device: %w", err)
	}
	return nil
}

func scanIoTDevice(r pgx.Row) (theauth.Device, error) {
	var (
		id, org                           pgtype.UUID
		name, jwk, thumb, att, scopes, st string
		spiffe                            *string
		created, lastSeen, revoked        pgtype.Timestamptz
	)
	if err := r.Scan(&id, &org, &name, &spiffe, &jwk, &thumb, &att, &scopes, &st, &created, &lastSeen, &revoked); err != nil {
		return theauth.Device{}, err
	}
	sc, err := decodeList(scopes)
	if err != nil {
		return theauth.Device{}, err
	}
	d := theauth.Device{
		ID: pgUUIDToULID(id), OrganizationID: uuidToPtr(org), Name: name, PublicKeyJWK: []byte(jwk),
		KeyThumbprint: thumb, Attestation: att, Scopes: sc, Status: st,
		CreatedAt: tsToTime(created).UTC(), LastSeenAt: utcPtr(lastSeen), RevokedAt: utcPtr(revoked),
	}
	if spiffe != nil {
		d.SPIFFEID = *spiffe
	}
	return d, nil
}

func (s *Store) DeviceByID(ctx context.Context, id theauth.ULID) (*theauth.Device, error) {
	d, err := scanIoTDevice(s.pool.QueryRow(ctx, `SELECT `+iotDeviceCols+` FROM iot_devices WHERE id = $1`, ulidToPgUUID(id)))
	if err != nil {
		return nil, notFoundOr("device by id", err)
	}
	return &d, nil
}

func (s *Store) ListDevices(ctx context.Context, orgID *theauth.ULID) ([]theauth.Device, error) {
	q := `SELECT ` + iotDeviceCols + ` FROM iot_devices`
	args := []any{}
	if orgID != nil {
		q += ` WHERE organization_id = $1`
		args = append(args, ulidToPgUUID(*orgID))
	}
	q += ` ORDER BY created_at DESC, id DESC`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list devices: %w", err)
	}
	defer rows.Close()
	var out []theauth.Device
	for rows.Next() {
		d, err := scanIoTDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: list devices: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) RevokeDevice(ctx context.Context, id theauth.ULID, at time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE iot_devices SET status = 'revoked', revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`,
		ulidToPgUUID(id), at)
	if err != nil {
		return false, fmt.Errorf("postgres: revoke device: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) TouchDevice(ctx context.Context, id theauth.ULID, at time.Time) error {
	if _, err := s.pool.Exec(ctx, `UPDATE iot_devices SET last_seen_at = $2 WHERE id = $1`, ulidToPgUUID(id), at); err != nil {
		return fmt.Errorf("postgres: touch device: %w", err)
	}
	return nil
}

func (s *Store) InsertDeviceJoinToken(ctx context.Context, t theauth.DeviceJoinToken) error {
	scopes, err := encodeList(t.Scopes)
	if err != nil {
		return fmt.Errorf("postgres: insert device join token: %w", err)
	}
	created := t.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO device_join_tokens (`+joinTokenCols+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		ulidToPgUUID(t.ID), t.TokenHash, t.Prefix, uuidPtr(t.OrganizationID), t.Name, t.SPIFFEID, scopes,
		uuidPtr(t.CreatedBy), created, t.ExpiresAt, timePtrToTs(t.RedeemedAt), uuidPtr(t.DeviceID), timePtrToTs(t.RevokedAt), t.EffectiveMaxUses(), t.Uses)
	if err != nil {
		return fmt.Errorf("postgres: insert device join token: %w", err)
	}
	return nil
}

func scanJoinToken(r pgx.Row) (theauth.DeviceJoinToken, error) {
	var (
		id, org, by, dev               pgtype.UUID
		hash                           []byte
		prefix, name, spiffe, scopes   string
		created, expires, redeemed, rv pgtype.Timestamptz
		maxUses, uses                  int
	)
	if err := r.Scan(&id, &hash, &prefix, &org, &name, &spiffe, &scopes, &by, &created, &expires, &redeemed, &dev, &rv, &maxUses, &uses); err != nil {
		return theauth.DeviceJoinToken{}, err
	}
	sc, err := decodeList(scopes)
	if err != nil {
		return theauth.DeviceJoinToken{}, err
	}
	return theauth.DeviceJoinToken{
		ID: pgUUIDToULID(id), TokenHash: hash, Prefix: prefix, OrganizationID: uuidToPtr(org), Name: name,
		SPIFFEID: spiffe, Scopes: sc, CreatedBy: uuidToPtr(by), CreatedAt: tsToTime(created).UTC(),
		ExpiresAt: tsToTime(expires).UTC(), RedeemedAt: utcPtr(redeemed), DeviceID: uuidToPtr(dev), RevokedAt: utcPtr(rv),
		MaxUses: maxUses, Uses: uses,
	}, nil
}

func (s *Store) DeviceJoinTokenByHash(ctx context.Context, hash []byte) (*theauth.DeviceJoinToken, error) {
	t, err := scanJoinToken(s.pool.QueryRow(ctx, `SELECT `+joinTokenCols+` FROM device_join_tokens WHERE token_hash = $1`, hash))
	if err != nil {
		return nil, notFoundOr("device join token by hash", err)
	}
	return &t, nil
}

func (s *Store) DeviceJoinTokenByID(ctx context.Context, id theauth.ULID) (*theauth.DeviceJoinToken, error) {
	t, err := scanJoinToken(s.pool.QueryRow(ctx, `SELECT `+joinTokenCols+` FROM device_join_tokens WHERE id = $1`, ulidToPgUUID(id)))
	if err != nil {
		return nil, notFoundOr("device join token by id", err)
	}
	return &t, nil
}

func (s *Store) RevokeDeviceJoinToken(ctx context.Context, id theauth.ULID, at time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE device_join_tokens SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, ulidToPgUUID(id), at)
	if err != nil {
		return false, fmt.Errorf("postgres: revoke device join token: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) RedeemDeviceJoinToken(ctx context.Context, id, deviceID theauth.ULID, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE device_join_tokens SET
redeemed_at = CASE WHEN uses + 1 >= max_uses THEN $3::timestamptz ELSE NULL END,
device_id = CASE WHEN max_uses = 1 THEN $2::uuid ELSE NULL END,
uses = uses + 1
WHERE id = $1 AND uses < max_uses AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > $3`,
		ulidToPgUUID(id), ulidToPgUUID(deviceID), now)
	if err != nil {
		return false, fmt.Errorf("postgres: redeem device join token: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) RefundDeviceJoinToken(ctx context.Context, id theauth.ULID) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE device_join_tokens SET redeemed_at = NULL, device_id = NULL, uses = GREATEST(uses - 1, 0) WHERE id = $1`,
		ulidToPgUUID(id)); err != nil {
		return fmt.Errorf("postgres: refund device join token: %w", err)
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
	tag, err := s.pool.Exec(ctx,
		`UPDATE iot_devices SET status = $3 WHERE id = $1 AND status = $2 AND revoked_at IS NULL`,
		ulidToPgUUID(id), from, to)
	if err != nil {
		return false, fmt.Errorf("postgres: set device status: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) DeviceBySPIFFEID(ctx context.Context, spiffeID string) (*theauth.Device, error) {
	if spiffeID == "" {
		return nil, theauth.ErrStorageNotFound
	}
	d, err := scanIoTDevice(s.pool.QueryRow(ctx, `SELECT `+iotDeviceCols+` FROM iot_devices WHERE spiffe_id = $1`, spiffeID))
	if err != nil {
		return nil, notFoundOr("device by spiffe id", err)
	}
	return &d, nil
}

func (s *Store) DeviceByKeyThumbprint(ctx context.Context, thumbprint string) (*theauth.Device, error) {
	if thumbprint == "" {
		return nil, theauth.ErrStorageNotFound
	}
	d, err := scanIoTDevice(s.pool.QueryRow(ctx, `SELECT `+iotDeviceCols+
		` FROM iot_devices WHERE key_thumbprint = $1 ORDER BY created_at DESC, id DESC LIMIT 1`, thumbprint))
	if err != nil {
		return nil, notFoundOr("device by key thumbprint", err)
	}
	return &d, nil
}
