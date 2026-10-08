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

// postgres_device.go: DeviceAuthorizationStorage (RFC 8628 device grant) and
// RegistrationTokenStorage (initial access tokens) over migration 0019.

var (
	_ theauth.DeviceAuthorizationStorage = (*Store)(nil)
	_ theauth.RegistrationTokenStorage   = (*Store)(nil)
)

const devAuthCols = `id, device_code_hash, user_code_hash, client_id, scope, resource, status, user_id,
interval_seconds, last_poll_at, created_at, expires_at, decided_at`

const regTokenCols = `id, token_hash, token_prefix, label, organization_id, scopes, grant_types, max_uses, uses,
created_by, created_at, expires_at, last_used_at, revoked_at`

// InsertDeviceAuthorization satisfies DeviceAuthorizationStorage.
func (s *Store) InsertDeviceAuthorization(ctx context.Context, d theauth.DeviceAuthorization) error {
	scope, err := encodeList(d.Scope)
	if err != nil {
		return fmt.Errorf("postgres: insert device authorization: %w", err)
	}
	created := d.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	// An expired holder of the same user code must not block reuse.
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM device_authorizations WHERE user_code_hash = $1 AND expires_at <= $2`,
		d.UserCodeHash, time.Now()); err != nil {
		return fmt.Errorf("postgres: insert device authorization: %w", err)
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO device_authorizations (`+devAuthCols+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		ulidToPgUUID(d.ID), d.DeviceCodeHash, d.UserCodeHash, d.ClientID, scope, d.Resource, d.Status,
		uuidPtr(d.UserID), int32(d.IntervalSeconds), timePtrToTs(d.LastPollAt), created, d.ExpiresAt,
		timePtrToTs(d.DecidedAt))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation &&
			pgErr.ConstraintName == "device_authorizations_user_hash_uq" {
			return theauth.ErrDeviceAuthUserCodeTaken
		}
		return fmt.Errorf("postgres: insert device authorization: %w", err)
	}
	return nil
}

func scanDevAuth(r pgx.Row) (theauth.DeviceAuthorization, error) {
	var (
		id, user                     pgtype.UUID
		dHash, uHash                 []byte
		client, scope, resource, st  string
		interval                     int32
		polled, created, expires, dc pgtype.Timestamptz
	)
	if err := r.Scan(&id, &dHash, &uHash, &client, &scope, &resource, &st, &user, &interval,
		&polled, &created, &expires, &dc); err != nil {
		return theauth.DeviceAuthorization{}, err
	}
	sc, err := decodeList(scope)
	if err != nil {
		return theauth.DeviceAuthorization{}, err
	}
	return theauth.DeviceAuthorization{
		ID: pgUUIDToULID(id), DeviceCodeHash: dHash, UserCodeHash: uHash, ClientID: client, Scope: sc,
		Resource: resource, Status: st, UserID: uuidToPtr(user), IntervalSeconds: int(interval),
		LastPollAt: utcPtr(polled), CreatedAt: tsToTime(created).UTC(), ExpiresAt: tsToTime(expires).UTC(),
		DecidedAt: utcPtr(dc),
	}, nil
}

// DeviceAuthorizationByDeviceCodeHash satisfies DeviceAuthorizationStorage.
func (s *Store) DeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash []byte) (*theauth.DeviceAuthorization, error) {
	d, err := scanDevAuth(s.pool.QueryRow(ctx,
		`SELECT `+devAuthCols+` FROM device_authorizations WHERE device_code_hash = $1`, hash))
	if err != nil {
		return nil, notFoundOr("device authorization by device code", err)
	}
	return &d, nil
}

// DeviceAuthorizationByUserCodeHash satisfies DeviceAuthorizationStorage.
func (s *Store) DeviceAuthorizationByUserCodeHash(ctx context.Context, hash []byte) (*theauth.DeviceAuthorization, error) {
	d, err := scanDevAuth(s.pool.QueryRow(ctx,
		`SELECT `+devAuthCols+` FROM device_authorizations WHERE user_code_hash = $1`, hash))
	if err != nil {
		return nil, notFoundOr("device authorization by user code", err)
	}
	return &d, nil
}

// DecideDeviceAuthorization satisfies DeviceAuthorizationStorage.
func (s *Store) DecideDeviceAuthorization(ctx context.Context, id theauth.ULID, status string, userID theauth.ULID, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE device_authorizations
SET status = $2, user_id = $3, decided_at = $4
WHERE id = $1 AND status = 'pending' AND expires_at > $4`, ulidToPgUUID(id), status, ulidToPgUUID(userID), now)
	if err != nil {
		return false, fmt.Errorf("postgres: decide device authorization: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RecordDeviceAuthorizationPoll satisfies DeviceAuthorizationStorage.
func (s *Store) RecordDeviceAuthorizationPoll(ctx context.Context, id theauth.ULID, polledAt time.Time, intervalSeconds int) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE device_authorizations SET last_poll_at = $2, interval_seconds = $3 WHERE id = $1`,
		ulidToPgUUID(id), polledAt, int32(intervalSeconds))
	if err != nil {
		return fmt.Errorf("postgres: record device authorization poll: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: record device authorization poll: %w", theauth.ErrStorageNotFound)
	}
	return nil
}

// ConsumeDeviceAuthorization satisfies DeviceAuthorizationStorage.
func (s *Store) ConsumeDeviceAuthorization(ctx context.Context, id theauth.ULID, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE device_authorizations SET status = 'consumed'
WHERE id = $1 AND status = 'approved' AND expires_at > $2`, ulidToPgUUID(id), now)
	if err != nil {
		return false, fmt.Errorf("postgres: consume device authorization: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteExpiredDeviceAuthorizations satisfies DeviceAuthorizationStorage.
func (s *Store) DeleteExpiredDeviceAuthorizations(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM device_authorizations WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired device authorizations: %w", err)
	}
	return tag.RowsAffected(), nil
}

// InsertRegistrationToken satisfies RegistrationTokenStorage.
func (s *Store) InsertRegistrationToken(ctx context.Context, t theauth.RegistrationToken) error {
	scopes, err := encodeList(t.Scopes)
	if err != nil {
		return fmt.Errorf("postgres: insert registration token: %w", err)
	}
	grants, err := encodeList(t.GrantTypes)
	if err != nil {
		return fmt.Errorf("postgres: insert registration token: %w", err)
	}
	created := t.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO registration_tokens (`+regTokenCols+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		ulidToPgUUID(t.ID), t.TokenHash, t.Prefix, t.Label, uuidPtr(t.OrganizationID), scopes, grants,
		int32(t.MaxUses), int32(t.Uses), uuidPtr(t.CreatedBy), created, t.ExpiresAt,
		timePtrToTs(t.LastUsedAt), timePtrToTs(t.RevokedAt))
	if err != nil {
		return fmt.Errorf("postgres: insert registration token: %w", err)
	}
	return nil
}

func scanRegToken(r pgx.Row) (theauth.RegistrationToken, error) {
	var (
		id, org, by                         pgtype.UUID
		hash                                []byte
		prefix, label, scopes, grants       string
		maxUses, uses                       int32
		created, expires, lastUsed, revoked pgtype.Timestamptz
	)
	if err := r.Scan(&id, &hash, &prefix, &label, &org, &scopes, &grants, &maxUses, &uses, &by,
		&created, &expires, &lastUsed, &revoked); err != nil {
		return theauth.RegistrationToken{}, err
	}
	sc, err := decodeList(scopes)
	if err != nil {
		return theauth.RegistrationToken{}, err
	}
	gr, err := decodeList(grants)
	if err != nil {
		return theauth.RegistrationToken{}, err
	}
	return theauth.RegistrationToken{
		ID: pgUUIDToULID(id), TokenHash: hash, Prefix: prefix, Label: label, OrganizationID: uuidToPtr(org),
		Scopes: sc, GrantTypes: gr, MaxUses: int(maxUses), Uses: int(uses), CreatedBy: uuidToPtr(by),
		CreatedAt: tsToTime(created).UTC(), ExpiresAt: tsToTime(expires).UTC(),
		LastUsedAt: utcPtr(lastUsed), RevokedAt: utcPtr(revoked),
	}, nil
}

// RegistrationTokenByHash satisfies RegistrationTokenStorage.
func (s *Store) RegistrationTokenByHash(ctx context.Context, hash []byte) (*theauth.RegistrationToken, error) {
	t, err := scanRegToken(s.pool.QueryRow(ctx, `SELECT `+regTokenCols+` FROM registration_tokens WHERE token_hash = $1`, hash))
	if err != nil {
		return nil, notFoundOr("registration token by hash", err)
	}
	return &t, nil
}

// RegistrationTokenByID satisfies RegistrationTokenStorage.
func (s *Store) RegistrationTokenByID(ctx context.Context, id theauth.ULID) (*theauth.RegistrationToken, error) {
	t, err := scanRegToken(s.pool.QueryRow(ctx, `SELECT `+regTokenCols+` FROM registration_tokens WHERE id = $1`, ulidToPgUUID(id)))
	if err != nil {
		return nil, notFoundOr("registration token by id", err)
	}
	return &t, nil
}

// ListRegistrationTokens satisfies RegistrationTokenStorage.
func (s *Store) ListRegistrationTokens(ctx context.Context, orgID *theauth.ULID) ([]theauth.RegistrationToken, error) {
	q := `SELECT ` + regTokenCols + ` FROM registration_tokens`
	args := []any{}
	if orgID != nil {
		q += ` WHERE organization_id = $1`
		args = append(args, ulidToPgUUID(*orgID))
	}
	q += ` ORDER BY created_at DESC, id DESC`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list registration tokens: %w", err)
	}
	defer rows.Close()
	var out []theauth.RegistrationToken
	for rows.Next() {
		t, err := scanRegToken(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: list registration tokens: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeRegistrationToken satisfies RegistrationTokenStorage.
func (s *Store) RevokeRegistrationToken(ctx context.Context, id theauth.ULID, at time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE registration_tokens SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, ulidToPgUUID(id), at)
	if err != nil {
		return false, fmt.Errorf("postgres: revoke registration token: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RedeemRegistrationToken satisfies RegistrationTokenStorage.
func (s *Store) RedeemRegistrationToken(ctx context.Context, id theauth.ULID, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE registration_tokens SET uses = uses + 1, last_used_at = $2
WHERE id = $1 AND revoked_at IS NULL AND expires_at > $2 AND uses < max_uses`, ulidToPgUUID(id), now)
	if err != nil {
		return false, fmt.Errorf("postgres: redeem registration token: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RefundRegistrationToken satisfies RegistrationTokenStorage.
func (s *Store) RefundRegistrationToken(ctx context.Context, id theauth.ULID) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE registration_tokens SET uses = uses - 1 WHERE id = $1 AND uses > 0`, ulidToPgUUID(id)); err != nil {
		return fmt.Errorf("postgres: refund registration token: %w", err)
	}
	return nil
}
