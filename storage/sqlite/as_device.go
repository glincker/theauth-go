package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// as_device.go: RFC 8628 device authorizations (migration 0027) and initial
// access tokens (migration 0028).

const asDevAuthCols = `id, device_code_hash, user_code_hash, client_id, scope, resource, status, user_id,
	interval_seconds, last_poll_at, created_at, expires_at, decided_at`

const asRegTokenCols = `id, token_hash, token_prefix, label, organization_id, scopes, grant_types, max_uses, uses,
	created_by, created_at, expires_at, last_used_at, revoked_at`

// asIsUnique reports whether err is a SQLite UNIQUE constraint failure.
func asIsUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// InsertDeviceAuthorization implements theauth.DeviceAuthorizationStorage. An expired holder
// of the same user code is deleted first; a live one yields ErrDeviceAuthUserCodeTaken.
func (s *Store) InsertDeviceAuthorization(ctx context.Context, d theauth.DeviceAuthorization) error {
	scope, err := asEncodeList(d.Scope)
	if err != nil {
		return wrap("insert device authorization", err)
	}
	now := time.Now()
	err = s.inTx(ctx, "insert device authorization", func(tx DBTX) error {
		if _, err := tx.ExecContext(ctx, s.q(
			`DELETE FROM theauth_device_authorizations WHERE user_code_hash = ? AND expires_at <= ?`),
			d.UserCodeHash, toMicro(now)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.q(`INSERT INTO theauth_device_authorizations (`+asDevAuthCols+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			idStr(d.ID), d.DeviceCodeHash, d.UserCodeHash, d.ClientID, scope, d.Resource, d.Status,
			idPtrStr(d.UserID), d.IntervalSeconds, toNullMicro(d.LastPollAt), toMicro(orNow(d.CreatedAt)),
			toMicro(d.ExpiresAt), toNullMicro(d.DecidedAt))
		return err
	})
	if asIsUnique(err) && strings.Contains(err.Error(), "user_code_hash") {
		return theauth.ErrDeviceAuthUserCodeTaken
	}
	return err
}

func asScanDevAuth(r scanner) (theauth.DeviceAuthorization, error) {
	var (
		id, client, scope, resource, status string
		dHash, uHash                        []byte
		user                                sql.NullString
		interval                            int
		polled, decided                     sql.NullInt64
		created, expires                    int64
	)
	if err := r.Scan(&id, &dHash, &uHash, &client, &scope, &resource, &status, &user, &interval,
		&polled, &created, &expires, &decided); err != nil {
		return theauth.DeviceAuthorization{}, err
	}
	out := theauth.DeviceAuthorization{
		DeviceCodeHash: dHash, UserCodeHash: uHash, ClientID: client, Resource: resource, Status: status,
		IntervalSeconds: interval, LastPollAt: fromNullMicro(polled), CreatedAt: fromMicro(created),
		ExpiresAt: fromMicro(expires), DecidedAt: fromNullMicro(decided),
	}
	var err error
	if out.ID, err = parseID(id); err != nil {
		return theauth.DeviceAuthorization{}, err
	}
	if out.UserID, err = parseIDPtr(user); err != nil {
		return theauth.DeviceAuthorization{}, err
	}
	if out.Scope, err = asDecodeList(scope); err != nil {
		return theauth.DeviceAuthorization{}, err
	}
	return out, nil
}

func (s *Store) DeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash []byte) (*theauth.DeviceAuthorization, error) {
	d, err := asScanDevAuth(s.db.QueryRowContext(ctx, s.q(
		`SELECT `+asDevAuthCols+` FROM theauth_device_authorizations WHERE device_code_hash = ?`), hash))
	if err != nil {
		return nil, notFoundOr("device authorization by device code", err)
	}
	return &d, nil
}

func (s *Store) DeviceAuthorizationByUserCodeHash(ctx context.Context, hash []byte) (*theauth.DeviceAuthorization, error) {
	d, err := asScanDevAuth(s.db.QueryRowContext(ctx, s.q(
		`SELECT `+asDevAuthCols+` FROM theauth_device_authorizations WHERE user_code_hash = ?`), hash))
	if err != nil {
		return nil, notFoundOr("device authorization by user code", err)
	}
	return &d, nil
}

// DecideDeviceAuthorization implements theauth.DeviceAuthorizationStorage as a
// compare and set from pending to the given status.
func (s *Store) DecideDeviceAuthorization(ctx context.Context, id theauth.ULID, status string, userID theauth.ULID, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_device_authorizations SET status = ?, user_id = ?, decided_at = ?
WHERE id = ? AND status = 'pending' AND expires_at > ?`),
		status, idStr(userID), toMicro(now), idStr(id), toMicro(now))
	return rowWon(res, err, "decide device authorization")
}

func (s *Store) RecordDeviceAuthorizationPoll(ctx context.Context, id theauth.ULID, polledAt time.Time, intervalSeconds int) error {
	res, err := s.db.ExecContext(ctx, s.q(
		`UPDATE theauth_device_authorizations SET last_poll_at = ?, interval_seconds = ? WHERE id = ?`),
		toMicro(polledAt), intervalSeconds, idStr(id))
	if err != nil {
		return wrap("record device authorization poll", err)
	}
	return requireRows("record device authorization poll", res)
}

// ConsumeDeviceAuthorization implements theauth.DeviceAuthorizationStorage:
// approved to consumed, with exactly one winner under concurrency.
func (s *Store) ConsumeDeviceAuthorization(ctx context.Context, id theauth.ULID, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_device_authorizations SET status = 'consumed'
WHERE id = ? AND status = 'approved' AND expires_at > ?`), idStr(id), toMicro(now))
	return rowWon(res, err, "consume device authorization")
}

func (s *Store) DeleteExpiredDeviceAuthorizations(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM theauth_device_authorizations WHERE expires_at < ?`), toMicro(before))
	if err != nil {
		return 0, wrap("delete expired device authorizations", err)
	}
	n, err := res.RowsAffected()
	return n, wrap("delete expired device authorizations", err)
}

func (s *Store) InsertRegistrationToken(ctx context.Context, t theauth.RegistrationToken) error {
	scopes, err := asEncodeList(t.Scopes)
	if err != nil {
		return wrap("insert registration token", err)
	}
	grants, err := asEncodeList(t.GrantTypes)
	if err != nil {
		return wrap("insert registration token", err)
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO theauth_registration_tokens (`+asRegTokenCols+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		idStr(t.ID), t.TokenHash, t.Prefix, t.Label, idPtrStr(t.OrganizationID), scopes, grants,
		t.MaxUses, t.Uses, idPtrStr(t.CreatedBy), toMicro(orNow(t.CreatedAt)), toMicro(t.ExpiresAt),
		toNullMicro(t.LastUsedAt), toNullMicro(t.RevokedAt))
	return wrap("insert registration token", err)
}

func asScanRegToken(r scanner) (theauth.RegistrationToken, error) {
	var (
		id, prefix, label, scopes, grants string
		hash                              []byte
		org, by                           sql.NullString
		maxUses, uses                     int
		created, expires                  int64
		lastUsed, revoked                 sql.NullInt64
	)
	if err := r.Scan(&id, &hash, &prefix, &label, &org, &scopes, &grants, &maxUses, &uses, &by,
		&created, &expires, &lastUsed, &revoked); err != nil {
		return theauth.RegistrationToken{}, err
	}
	out := theauth.RegistrationToken{
		TokenHash: hash, Prefix: prefix, Label: label, MaxUses: maxUses, Uses: uses,
		CreatedAt: fromMicro(created), ExpiresAt: fromMicro(expires),
		LastUsedAt: fromNullMicro(lastUsed), RevokedAt: fromNullMicro(revoked),
	}
	var err error
	if out.ID, err = parseID(id); err != nil {
		return theauth.RegistrationToken{}, err
	}
	if out.OrganizationID, err = parseIDPtr(org); err != nil {
		return theauth.RegistrationToken{}, err
	}
	if out.CreatedBy, err = parseIDPtr(by); err != nil {
		return theauth.RegistrationToken{}, err
	}
	if out.Scopes, err = asDecodeList(scopes); err != nil {
		return theauth.RegistrationToken{}, err
	}
	if out.GrantTypes, err = asDecodeList(grants); err != nil {
		return theauth.RegistrationToken{}, err
	}
	return out, nil
}

func (s *Store) RegistrationTokenByHash(ctx context.Context, hash []byte) (*theauth.RegistrationToken, error) {
	t, err := asScanRegToken(s.db.QueryRowContext(ctx, s.q(
		`SELECT `+asRegTokenCols+` FROM theauth_registration_tokens WHERE token_hash = ?`), hash))
	if err != nil {
		return nil, notFoundOr("registration token by hash", err)
	}
	return &t, nil
}

func (s *Store) RegistrationTokenByID(ctx context.Context, id theauth.ULID) (*theauth.RegistrationToken, error) {
	t, err := asScanRegToken(s.db.QueryRowContext(ctx, s.q(
		`SELECT `+asRegTokenCols+` FROM theauth_registration_tokens WHERE id = ?`), idStr(id)))
	if err != nil {
		return nil, notFoundOr("registration token by id", err)
	}
	return &t, nil
}

// ListRegistrationTokens implements theauth.RegistrationTokenStorage, newest first.
func (s *Store) ListRegistrationTokens(ctx context.Context, orgID *theauth.ULID) ([]theauth.RegistrationToken, error) {
	q := `SELECT ` + asRegTokenCols + ` FROM theauth_registration_tokens`
	var args []any
	if orgID != nil {
		q += ` WHERE organization_id = ?`
		args = append(args, idStr(*orgID))
	}
	q += ` ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, s.q(q), args...)
	if err != nil {
		return nil, wrap("list registration tokens", err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.RegistrationToken
	for rows.Next() {
		t, err := asScanRegToken(rows)
		if err != nil {
			return nil, wrap("list registration tokens", err)
		}
		out = append(out, t)
	}
	return out, wrap("list registration tokens", rows.Err())
}

func (s *Store) RevokeRegistrationToken(ctx context.Context, id theauth.ULID, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(
		`UPDATE theauth_registration_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`), toMicro(at), idStr(id))
	return rowWon(res, err, "revoke registration token")
}

// RedeemRegistrationToken implements theauth.RegistrationTokenStorage. The uses < max_uses
// guard keeps a one-time token to one winner.
func (s *Store) RedeemRegistrationToken(ctx context.Context, id theauth.ULID, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_registration_tokens SET uses = uses + 1, last_used_at = ?
WHERE id = ? AND revoked_at IS NULL AND expires_at > ? AND uses < max_uses`),
		toMicro(now), idStr(id), toMicro(now))
	return rowWon(res, err, "redeem registration token")
}

func (s *Store) RefundRegistrationToken(ctx context.Context, id theauth.ULID) error {
	_, err := s.db.ExecContext(ctx, s.q(
		`UPDATE theauth_registration_tokens SET uses = uses - 1 WHERE id = ? AND uses > 0`), idStr(id))
	return wrap("refund registration token", err)
}
