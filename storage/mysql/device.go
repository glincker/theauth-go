package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// device.go: DeviceAuthorizationStorage (RFC 8628 device grant) and
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
		return fmt.Errorf("mysql: insert device authorization: %w", err)
	}
	created := d.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	// An expired holder of the same user code must not block reuse.
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM device_authorizations WHERE user_code_hash = ? AND expires_at <= ?`,
		d.UserCodeHash, timeUTC(time.Now())); err != nil {
		return fmt.Errorf("mysql: insert device authorization: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO device_authorizations (`+devAuthCols+`)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ulidToBytes(d.ID), d.DeviceCodeHash, d.UserCodeHash, d.ClientID, scope, d.Resource, d.Status,
		ulidPtrToBytes(d.UserID), d.IntervalSeconds, timePtrToNull(d.LastPollAt), timeUTC(created),
		timeUTC(d.ExpiresAt), timePtrToNull(d.DecidedAt))
	if err != nil {
		if isMySQL1062(err) && strings.Contains(err.Error(), "uq_device_authz_user_hash") {
			return theauth.ErrDeviceAuthUserCodeTaken
		}
		return fmt.Errorf("mysql: insert device authorization: %w", err)
	}
	return nil
}

func scanDevAuth(r rowScanner) (theauth.DeviceAuthorization, error) {
	var (
		idB, userB, dHash, uHash []byte
		client, scope, resource  string
		status                   string
		interval                 int
		polled, decided          sql.NullTime
		created, expires         time.Time
	)
	if err := r.Scan(&idB, &dHash, &uHash, &client, &scope, &resource, &status, &userB, &interval,
		&polled, &created, &expires, &decided); err != nil {
		return theauth.DeviceAuthorization{}, err
	}
	sc, err := decodeList(scope)
	if err != nil {
		return theauth.DeviceAuthorization{}, err
	}
	return theauth.DeviceAuthorization{
		ID: bytesToULID(idB), DeviceCodeHash: dHash, UserCodeHash: uHash, ClientID: client, Scope: sc,
		Resource: resource, Status: status, UserID: bytesToULIDPtr(userB), IntervalSeconds: interval,
		LastPollAt: nullTimeToPtr(polled), CreatedAt: created.UTC(), ExpiresAt: expires.UTC(),
		DecidedAt: nullTimeToPtr(decided),
	}, nil
}

// DeviceAuthorizationByDeviceCodeHash satisfies DeviceAuthorizationStorage.
func (s *Store) DeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash []byte) (*theauth.DeviceAuthorization, error) {
	d, err := scanDevAuth(s.db.QueryRowContext(ctx,
		`SELECT `+devAuthCols+` FROM device_authorizations WHERE device_code_hash = ?`, hash))
	if err != nil {
		return nil, notFoundOr("device authorization by device code", err)
	}
	return &d, nil
}

// DeviceAuthorizationByUserCodeHash satisfies DeviceAuthorizationStorage.
func (s *Store) DeviceAuthorizationByUserCodeHash(ctx context.Context, hash []byte) (*theauth.DeviceAuthorization, error) {
	d, err := scanDevAuth(s.db.QueryRowContext(ctx,
		`SELECT `+devAuthCols+` FROM device_authorizations WHERE user_code_hash = ?`, hash))
	if err != nil {
		return nil, notFoundOr("device authorization by user code", err)
	}
	return &d, nil
}

func rowsOne(res sql.Result, err error, op string) (bool, error) {
	if err != nil {
		return false, fmt.Errorf("mysql: %s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("mysql: %s: %w", op, err)
	}
	return n == 1, nil
}

// DecideDeviceAuthorization satisfies DeviceAuthorizationStorage.
func (s *Store) DecideDeviceAuthorization(ctx context.Context, id theauth.ULID, status string, userID theauth.ULID, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE device_authorizations
SET status = ?, user_id = ?, decided_at = ?
WHERE id = ? AND status = 'pending' AND expires_at > ?`,
		status, ulidToBytes(userID), timeUTC(now), ulidToBytes(id), timeUTC(now))
	return rowsOne(res, err, "decide device authorization")
}

// RecordDeviceAuthorizationPoll satisfies DeviceAuthorizationStorage.
func (s *Store) RecordDeviceAuthorizationPoll(ctx context.Context, id theauth.ULID, polledAt time.Time, intervalSeconds int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_authorizations SET last_poll_at = ?, interval_seconds = ? WHERE id = ?`,
		timeUTC(polledAt), intervalSeconds, ulidToBytes(id))
	if err != nil {
		return fmt.Errorf("mysql: record device authorization poll: %w", err)
	}
	return nil
}

// ConsumeDeviceAuthorization satisfies DeviceAuthorizationStorage.
func (s *Store) ConsumeDeviceAuthorization(ctx context.Context, id theauth.ULID, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE device_authorizations SET status = 'consumed'
WHERE id = ? AND status = 'approved' AND expires_at > ?`, ulidToBytes(id), timeUTC(now))
	return rowsOne(res, err, "consume device authorization")
}

// DeleteExpiredDeviceAuthorizations satisfies DeviceAuthorizationStorage.
func (s *Store) DeleteExpiredDeviceAuthorizations(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM device_authorizations WHERE expires_at < ?`, timeUTC(before))
	if err != nil {
		return 0, fmt.Errorf("mysql: delete expired device authorizations: %w", err)
	}
	return res.RowsAffected()
}

// InsertRegistrationToken satisfies RegistrationTokenStorage.
func (s *Store) InsertRegistrationToken(ctx context.Context, t theauth.RegistrationToken) error {
	scopes, err := encodeList(t.Scopes)
	if err != nil {
		return fmt.Errorf("mysql: insert registration token: %w", err)
	}
	grants, err := encodeList(t.GrantTypes)
	if err != nil {
		return fmt.Errorf("mysql: insert registration token: %w", err)
	}
	created := t.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO registration_tokens (`+regTokenCols+`)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ulidToBytes(t.ID), t.TokenHash, t.Prefix, t.Label, ulidPtrToBytes(t.OrganizationID), scopes, grants,
		t.MaxUses, t.Uses, ulidPtrToBytes(t.CreatedBy), timeUTC(created), timeUTC(t.ExpiresAt),
		timePtrToNull(t.LastUsedAt), timePtrToNull(t.RevokedAt))
	if err != nil {
		return fmt.Errorf("mysql: insert registration token: %w", err)
	}
	return nil
}

func scanRegToken(r rowScanner) (theauth.RegistrationToken, error) {
	var (
		idB, orgB, byB, hash          []byte
		prefix, label, scopes, grants string
		maxUses, uses                 int
		created, expires              time.Time
		lastUsed, revoked             sql.NullTime
	)
	if err := r.Scan(&idB, &hash, &prefix, &label, &orgB, &scopes, &grants, &maxUses, &uses, &byB,
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
		ID: bytesToULID(idB), TokenHash: hash, Prefix: prefix, Label: label, OrganizationID: bytesToULIDPtr(orgB),
		Scopes: sc, GrantTypes: gr, MaxUses: maxUses, Uses: uses, CreatedBy: bytesToULIDPtr(byB),
		CreatedAt: created.UTC(), ExpiresAt: expires.UTC(),
		LastUsedAt: nullTimeToPtr(lastUsed), RevokedAt: nullTimeToPtr(revoked),
	}, nil
}

// RegistrationTokenByHash satisfies RegistrationTokenStorage.
func (s *Store) RegistrationTokenByHash(ctx context.Context, hash []byte) (*theauth.RegistrationToken, error) {
	t, err := scanRegToken(s.db.QueryRowContext(ctx, `SELECT `+regTokenCols+` FROM registration_tokens WHERE token_hash = ?`, hash))
	if err != nil {
		return nil, notFoundOr("registration token by hash", err)
	}
	return &t, nil
}

// RegistrationTokenByID satisfies RegistrationTokenStorage.
func (s *Store) RegistrationTokenByID(ctx context.Context, id theauth.ULID) (*theauth.RegistrationToken, error) {
	t, err := scanRegToken(s.db.QueryRowContext(ctx, `SELECT `+regTokenCols+` FROM registration_tokens WHERE id = ?`, ulidToBytes(id)))
	if err != nil {
		return nil, notFoundOr("registration token by id", err)
	}
	return &t, nil
}

// ListRegistrationTokens satisfies RegistrationTokenStorage.
func (s *Store) ListRegistrationTokens(ctx context.Context, orgID *theauth.ULID) ([]theauth.RegistrationToken, error) {
	q := `SELECT ` + regTokenCols + ` FROM registration_tokens`
	var args []any
	if orgID != nil {
		q += ` WHERE organization_id = ?`
		args = append(args, ulidToBytes(*orgID))
	}
	q += ` ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("mysql: list registration tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.RegistrationToken
	for rows.Next() {
		t, err := scanRegToken(rows)
		if err != nil {
			return nil, fmt.Errorf("mysql: list registration tokens: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeRegistrationToken satisfies RegistrationTokenStorage.
func (s *Store) RevokeRegistrationToken(ctx context.Context, id theauth.ULID, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE registration_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, timeUTC(at), ulidToBytes(id))
	return rowsOne(res, err, "revoke registration token")
}

// RedeemRegistrationToken satisfies RegistrationTokenStorage.
func (s *Store) RedeemRegistrationToken(ctx context.Context, id theauth.ULID, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE registration_tokens SET uses = uses + 1, last_used_at = ?
WHERE id = ? AND revoked_at IS NULL AND expires_at > ? AND uses < max_uses`, timeUTC(now), ulidToBytes(id), timeUTC(now))
	return rowsOne(res, err, "redeem registration token")
}

// RefundRegistrationToken satisfies RegistrationTokenStorage.
func (s *Store) RefundRegistrationToken(ctx context.Context, id theauth.ULID) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE registration_tokens SET uses = uses - 1 WHERE id = ? AND uses > 0`, ulidToBytes(id)); err != nil {
		return fmt.Errorf("mysql: refund registration token: %w", err)
	}
	return nil
}
