package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	_ theauth.APITokenStorage   = (*Store)(nil)
	_ theauth.DeviceCodeStorage = (*Store)(nil)
	_ theauth.DeviceCodeLister  = (*Store)(nil)
)

const apiTokenCols = `id, owner_id, owner_kind, name, abilities, token_hash, hint, created_at, expires_at, last_used_at, revoked_at, kind, agent_name, delegated_by`

const deviceCols = `id, device_code_hash, user_code, status, client_name, requested_abilities, approved_abilities,
approver_id, requester_ip, requester_ua, interval_seconds, last_polled_at, created_at, expires_at`

const pgUniqueViolation = "23505"

func encodeList(v []string) (string, error) {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode list: %w", err)
	}
	return string(b), nil
}

func decodeList(s string) ([]string, error) {
	var v []string
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, fmt.Errorf("decode stored list %q: %w", s, err)
	}
	return v, nil
}

func uuidPtr(p *theauth.ULID) pgtype.UUID {
	if p == nil {
		return pgtype.UUID{}
	}
	return ulidToPgUUID(*p)
}

func uuidToPtr(u pgtype.UUID) *theauth.ULID {
	if !u.Valid {
		return nil
	}
	id := pgUUIDToULID(u)
	return &id
}

func utcPtr(ts pgtype.Timestamptz) *time.Time {
	t := tsToTimePtr(ts)
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func scanAPIToken(r pgx.Row) (theauth.APIToken, error) {
	var (
		id, owner, delegated             pgtype.UUID
		ownerKind, name, abilities, hint string
		kind, agentName                  string
		hash                             []byte
		created, expires, used, revoked  pgtype.Timestamptz
	)
	if err := r.Scan(&id, &owner, &ownerKind, &name, &abilities, &hash, &hint, &created, &expires, &used, &revoked,
		&kind, &agentName, &delegated); err != nil {
		return theauth.APIToken{}, err
	}
	ab, err := decodeList(abilities)
	if err != nil {
		return theauth.APIToken{}, err
	}
	return theauth.APIToken{
		ID: pgUUIDToULID(id), OwnerID: pgUUIDToULID(owner), OwnerKind: ownerKind, Name: name, Abilities: ab,
		TokenHash: hash, Hint: hint, Kind: kind, AgentName: agentName, DelegatedBy: uuidToPtr(delegated),
		CreatedAt: tsToTime(created).UTC(), ExpiresAt: utcPtr(expires), LastUsedAt: utcPtr(used), RevokedAt: utcPtr(revoked),
	}, nil
}

func notFoundOr(op string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: %s: %w", op, storage.ErrNotFound)
	}
	return fmt.Errorf("postgres: %s: %w", op, err)
}

// InsertAPIToken stores a token and returns the stored row.
func (s *Store) InsertAPIToken(ctx context.Context, t theauth.APIToken) (theauth.APIToken, error) {
	abilities, err := encodeList(t.Abilities)
	if err != nil {
		return theauth.APIToken{}, fmt.Errorf("postgres: insert api token: %w", err)
	}
	created := t.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	out, err := scanAPIToken(s.pool.QueryRow(ctx, `
INSERT INTO api_tokens (id, owner_id, owner_kind, name, abilities, token_hash, hint, created_at, expires_at, last_used_at, revoked_at, kind, agent_name, delegated_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
RETURNING `+apiTokenCols,
		ulidToPgUUID(t.ID), ulidToPgUUID(t.OwnerID), t.OwnerKind, t.Name, abilities, t.TokenHash, t.Hint,
		created, timePtrToTs(t.ExpiresAt), timePtrToTs(t.LastUsedAt), timePtrToTs(t.RevokedAt),
		t.Kind, t.AgentName, uuidPtr(t.DelegatedBy)))
	if err != nil {
		return theauth.APIToken{}, fmt.Errorf("postgres: insert api token: %w", err)
	}
	return out, nil
}

// APITokenByHash returns the token with the given secret hash, else ErrNotFound.
func (s *Store) APITokenByHash(ctx context.Context, hash []byte) (*theauth.APIToken, error) {
	t, err := scanAPIToken(s.pool.QueryRow(ctx, `SELECT `+apiTokenCols+` FROM api_tokens WHERE token_hash = $1`, hash))
	if err != nil {
		return nil, notFoundOr("api token by hash", err)
	}
	return &t, nil
}

// APITokenByID returns the token with the given ID, else ErrNotFound.
func (s *Store) APITokenByID(ctx context.Context, id theauth.ULID) (*theauth.APIToken, error) {
	t, err := scanAPIToken(s.pool.QueryRow(ctx, `SELECT `+apiTokenCols+` FROM api_tokens WHERE id = $1`, ulidToPgUUID(id)))
	if err != nil {
		return nil, notFoundOr("api token by id", err)
	}
	return &t, nil
}

func (s *Store) queryAPITokens(ctx context.Context, op, where string, args ...any) ([]theauth.APIToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+apiTokenCols+` FROM api_tokens `+where+` ORDER BY created_at DESC, id DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: %s: %w", op, err)
	}
	defer rows.Close()
	out := []theauth.APIToken{}
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: %s: %w", op, err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: %s: %w", op, err)
	}
	return out, nil
}

// APITokensByOwner returns every token of the owner, newest first.
func (s *Store) APITokensByOwner(ctx context.Context, ownerID theauth.ULID) ([]theauth.APIToken, error) {
	return s.queryAPITokens(ctx, "api tokens by owner", `WHERE owner_id = $1`, ulidToPgUUID(ownerID))
}

// ListAPITokens returns every token, newest first.
func (s *Store) ListAPITokens(ctx context.Context) ([]theauth.APIToken, error) {
	return s.queryAPITokens(ctx, "list api tokens", ``)
}

// RevokeAPIToken revokes a token, keeping the first revocation time on repeat calls.
func (s *Store) RevokeAPIToken(ctx context.Context, id theauth.ULID, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1`, ulidToPgUUID(id), at)
	if err != nil {
		return fmt.Errorf("postgres: revoke api token: %w", err)
	}
	return requireOne("revoke api token", tag.RowsAffected())
}

// RevokeAPITokensByOwner revokes the owner's live tokens and returns how many it changed.
func (s *Store) RevokeAPITokensByOwner(ctx context.Context, ownerID theauth.ULID, at time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE api_tokens SET revoked_at = $2 WHERE owner_id = $1 AND revoked_at IS NULL`, ulidToPgUUID(ownerID), at)
	if err != nil {
		return 0, fmt.Errorf("postgres: revoke api tokens by owner: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// TouchAPITokenLastUsed records the last use time of a token.
func (s *Store) TouchAPITokenLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at = $2 WHERE id = $1`, ulidToPgUUID(id), at)
	if err != nil {
		return fmt.Errorf("postgres: touch api token: %w", err)
	}
	return requireOne("touch api token", tag.RowsAffected())
}

func scanDevice(r pgx.Row) (theauth.DeviceCode, error) {
	var (
		id, approver                                   pgtype.UUID
		userCode, status, client, reqAb, appAb, ip, ua string
		hash                                           []byte
		interval                                       int32
		polled, created, expires                       pgtype.Timestamptz
	)
	if err := r.Scan(&id, &hash, &userCode, &status, &client, &reqAb, &appAb, &approver, &ip, &ua,
		&interval, &polled, &created, &expires); err != nil {
		return theauth.DeviceCode{}, err
	}
	req, err := decodeList(reqAb)
	if err != nil {
		return theauth.DeviceCode{}, err
	}
	app, err := decodeList(appAb)
	if err != nil {
		return theauth.DeviceCode{}, err
	}
	if len(app) == 0 {
		app = nil
	}
	return theauth.DeviceCode{
		ID: pgUUIDToULID(id), DeviceCodeHash: hash, UserCode: userCode, Status: status, ClientName: client,
		RequestedAbilities: req, ApprovedAbilities: app, ApproverID: uuidToPtr(approver), RequesterIP: ip, RequesterUA: ua,
		IntervalSeconds: int(interval), LastPolledAt: utcPtr(polled),
		CreatedAt: tsToTime(created).UTC(), ExpiresAt: tsToTime(expires).UTC(),
	}, nil
}

// InsertDeviceCode stores a request, returning ErrDeviceUserCodeTaken on a user code collision.
func (s *Store) InsertDeviceCode(ctx context.Context, d theauth.DeviceCode) error {
	req, err := encodeList(d.RequestedAbilities)
	if err != nil {
		return fmt.Errorf("postgres: insert device code: %w", err)
	}
	app, err := encodeList(d.ApprovedAbilities)
	if err != nil {
		return fmt.Errorf("postgres: insert device code: %w", err)
	}
	created := d.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO device_codes (`+deviceCols+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		ulidToPgUUID(d.ID), d.DeviceCodeHash, d.UserCode, d.Status, d.ClientName, req, app, uuidPtr(d.ApproverID),
		d.RequesterIP, d.RequesterUA, int32(d.IntervalSeconds), timePtrToTs(d.LastPolledAt), created, d.ExpiresAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "device_codes_user_code_uq" {
			return theauth.ErrDeviceUserCodeTaken
		}
		return fmt.Errorf("postgres: insert device code: %w", err)
	}
	return nil
}

// DeviceCodeByUserCode returns the request with the given user code, else ErrNotFound.
func (s *Store) DeviceCodeByUserCode(ctx context.Context, userCode string) (*theauth.DeviceCode, error) {
	d, err := scanDevice(s.pool.QueryRow(ctx, `SELECT `+deviceCols+` FROM device_codes WHERE user_code = $1`, userCode))
	if err != nil {
		return nil, notFoundOr("device code by user code", err)
	}
	return &d, nil
}

// DeviceCodeByHash returns the request with the given device code hash, else ErrNotFound.
func (s *Store) DeviceCodeByHash(ctx context.Context, hash []byte) (*theauth.DeviceCode, error) {
	d, err := scanDevice(s.pool.QueryRow(ctx, `SELECT `+deviceCols+` FROM device_codes WHERE device_code_hash = $1`, hash))
	if err != nil {
		return nil, notFoundOr("device code by hash", err)
	}
	return &d, nil
}

// DecideDeviceCode moves a pending, unexpired request to approved or denied in one statement.
func (s *Store) DecideDeviceCode(ctx context.Context, userCode string, d theauth.DeviceDecision, now time.Time) error {
	status, abilities := theauth.DeviceStatusDenied, "[]"
	if d.Approve {
		status = theauth.DeviceStatusApproved
		var err error
		if abilities, err = encodeList(d.Abilities); err != nil {
			return fmt.Errorf("postgres: decide device code: %w", err)
		}
	}
	tag, err := s.pool.Exec(ctx, `
UPDATE device_codes SET status = $1, approved_abilities = $2, approver_id = $3
WHERE user_code = $4 AND status = $5 AND expires_at > $6`,
		status, abilities, ulidToPgUUID(d.ApproverID), userCode, theauth.DeviceStatusPending, now)
	if err != nil {
		return fmt.Errorf("postgres: decide device code: %w", err)
	}
	return requireOne("decide device code", tag.RowsAffected())
}

// ClaimDeviceCode atomically moves an approved, unexpired request to redeemed; one concurrent caller wins.
func (s *Store) ClaimDeviceCode(ctx context.Context, hash []byte, now time.Time) (*theauth.DeviceCode, error) {
	d, err := scanDevice(s.pool.QueryRow(ctx, `
UPDATE device_codes SET status = $1
WHERE device_code_hash = $2 AND status = $3 AND expires_at > $4
RETURNING `+deviceCols, theauth.DeviceStatusRedeemed, hash, theauth.DeviceStatusApproved, now))
	if err != nil {
		return nil, notFoundOr("claim device code", err)
	}
	return &d, nil
}

// RecordDevicePoll stores the last poll time and the current polling interval.
func (s *Store) RecordDevicePoll(ctx context.Context, hash []byte, at time.Time, intervalSeconds int) error {
	tag, err := s.pool.Exec(ctx, `UPDATE device_codes SET last_polled_at = $1, interval_seconds = $2 WHERE device_code_hash = $3`,
		at, int32(intervalSeconds), hash)
	if err != nil {
		return fmt.Errorf("postgres: record device poll: %w", err)
	}
	return requireOne("record device poll", tag.RowsAffected())
}

// DeleteExpiredDeviceCodes removes requests that expired before the cutoff.
func (s *Store) DeleteExpiredDeviceCodes(ctx context.Context, before time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM device_codes WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired device codes: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ListPendingDeviceCodes returns pending, unexpired requests newest first without device code hashes.
func (s *Store) ListPendingDeviceCodes(ctx context.Context, f theauth.DevicePendingFilter) ([]theauth.DeviceCode, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+deviceCols+` FROM device_codes
WHERE status = $1 AND expires_at > $2 ORDER BY created_at DESC, id DESC LIMIT $3`,
		theauth.DeviceStatusPending, f.Now, int32(limit))
	if err != nil {
		return nil, fmt.Errorf("postgres: list pending device codes: %w", err)
	}
	defer rows.Close()
	var out []theauth.DeviceCode
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan pending device code: %w", err)
		}
		d.DeviceCodeHash = nil
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list pending device codes: %w", err)
	}
	return out, nil
}
