package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

var (
	_ theauth.APITokenStorage   = (*Store)(nil)
	_ theauth.DeviceCodeStorage = (*Store)(nil)
	_ theauth.DeviceCodeLister  = (*Store)(nil)
)

const apiTokenCols = `id, owner_id, owner_kind, name, abilities, token_hash, hint, created_at, expires_at, last_used_at, revoked_at, kind, agent_name, delegated_by`

const deviceCols = `id, device_code_hash, user_code, status, client_name, requested_abilities, approved_abilities,
approver_id, requester_ip, requester_ua, interval_seconds, last_polled_at, created_at, expires_at`

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

func notFoundOr(op string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("mysql: %s: %w", op, storage.ErrNotFound)
	}
	return fmt.Errorf("mysql: %s: %w", op, err)
}

type rowScanner interface{ Scan(dest ...any) error }

func scanAPIToken(r rowScanner) (theauth.APIToken, error) {
	var (
		idB, ownerB, delegatedB          []byte
		ownerKind, name, abilities, hint string
		kind, agentName                  string
		hash                             []byte
		created                          time.Time
		expires, used, revoked           sql.NullTime
	)
	if err := r.Scan(&idB, &ownerB, &ownerKind, &name, &abilities, &hash, &hint, &created, &expires, &used, &revoked,
		&kind, &agentName, &delegatedB); err != nil {
		return theauth.APIToken{}, err
	}
	ab, err := decodeList(abilities)
	if err != nil {
		return theauth.APIToken{}, err
	}
	return theauth.APIToken{
		ID: bytesToULID(idB), OwnerID: bytesToULID(ownerB), OwnerKind: ownerKind, Name: name, Abilities: ab,
		TokenHash: hash, Hint: hint, Kind: kind, AgentName: agentName, DelegatedBy: bytesToULIDPtr(delegatedB),
		CreatedAt: created.UTC(), ExpiresAt: nullTimeToPtr(expires), LastUsedAt: nullTimeToPtr(used), RevokedAt: nullTimeToPtr(revoked),
	}, nil
}

// InsertAPIToken stores a token and returns the stored row.
func (s *Store) InsertAPIToken(ctx context.Context, t theauth.APIToken) (theauth.APIToken, error) {
	abilities, err := encodeList(t.Abilities)
	if err != nil {
		return theauth.APIToken{}, fmt.Errorf("mysql: insert api token: %w", err)
	}
	created := t.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO api_tokens (`+apiTokenCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(t.ID), ulidToBytes(t.OwnerID), t.OwnerKind, t.Name, abilities, t.TokenHash, t.Hint,
		timeUTC(created), timePtrToNull(t.ExpiresAt), timePtrToNull(t.LastUsedAt), timePtrToNull(t.RevokedAt),
		t.Kind, t.AgentName, ulidPtrToBytes(t.DelegatedBy))
	if err != nil {
		return theauth.APIToken{}, fmt.Errorf("mysql: insert api token: %w", err)
	}
	got, err := s.APITokenByID(ctx, t.ID)
	if err != nil {
		return theauth.APIToken{}, err
	}
	return *got, nil
}

// APITokenByHash returns the token with the given secret hash, else ErrNotFound.
func (s *Store) APITokenByHash(ctx context.Context, hash []byte) (*theauth.APIToken, error) {
	t, err := scanAPIToken(s.db.QueryRowContext(ctx, `SELECT `+apiTokenCols+` FROM api_tokens WHERE token_hash = ?`, hash))
	if err != nil {
		return nil, notFoundOr("api token by hash", err)
	}
	return &t, nil
}

// APITokenByID returns the token with the given ID, else ErrNotFound.
func (s *Store) APITokenByID(ctx context.Context, id theauth.ULID) (*theauth.APIToken, error) {
	t, err := scanAPIToken(s.db.QueryRowContext(ctx, `SELECT `+apiTokenCols+` FROM api_tokens WHERE id = ?`, ulidToBytes(id)))
	if err != nil {
		return nil, notFoundOr("api token by id", err)
	}
	return &t, nil
}

func (s *Store) queryAPITokens(ctx context.Context, op, where string, args ...any) ([]theauth.APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+apiTokenCols+` FROM api_tokens `+where+` ORDER BY created_at DESC, id DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("mysql: %s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.APIToken{}
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, fmt.Errorf("mysql: %s: %w", op, err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mysql: %s: %w", op, err)
	}
	return out, nil
}

// APITokensByOwner returns every token of the owner, newest first.
func (s *Store) APITokensByOwner(ctx context.Context, ownerID theauth.ULID) ([]theauth.APIToken, error) {
	return s.queryAPITokens(ctx, "api tokens by owner", `WHERE owner_id = ?`, ulidToBytes(ownerID))
}

// ListAPITokens returns every token, newest first.
func (s *Store) ListAPITokens(ctx context.Context) ([]theauth.APIToken, error) {
	return s.queryAPITokens(ctx, "list api tokens", ``)
}

// RevokeAPIToken revokes a token, keeping the first revocation time on repeat calls.
func (s *Store) RevokeAPIToken(ctx context.Context, id theauth.ULID, at time.Time) error {
	return s.execOnRow(ctx, "revoke api token", "api_tokens", id,
		`UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, timeUTC(at), ulidToBytes(id))
}

// RevokeAPITokensByOwner revokes the owner's live tokens and returns how many it changed.
func (s *Store) RevokeAPITokensByOwner(ctx context.Context, ownerID theauth.ULID, at time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ? WHERE owner_id = ? AND revoked_at IS NULL`,
		timeUTC(at), ulidToBytes(ownerID))
	return rowsCount("revoke api tokens by owner", res, err)
}

// TouchAPITokenLastUsed records the last use time of a token.
func (s *Store) TouchAPITokenLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	return s.execOnRow(ctx, "touch api token", "api_tokens", id,
		`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, timeUTC(at), ulidToBytes(id))
}

func scanDevice(r rowScanner) (theauth.DeviceCode, error) {
	var (
		idB, approverB                                 []byte
		userCode, status, client, reqAb, appAb, ip, ua string
		hash                                           []byte
		interval                                       int
		polled                                         sql.NullTime
		created, expires                               time.Time
	)
	if err := r.Scan(&idB, &hash, &userCode, &status, &client, &reqAb, &appAb, &approverB, &ip, &ua,
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
		ID: bytesToULID(idB), DeviceCodeHash: hash, UserCode: userCode, Status: status, ClientName: client,
		RequestedAbilities: req, ApprovedAbilities: app, ApproverID: bytesToULIDPtr(approverB), RequesterIP: ip, RequesterUA: ua,
		IntervalSeconds: interval, LastPolledAt: nullTimeToPtr(polled), CreatedAt: created.UTC(), ExpiresAt: expires.UTC(),
	}, nil
}

// InsertDeviceCode stores a request, returning ErrDeviceUserCodeTaken on a user code collision.
func (s *Store) InsertDeviceCode(ctx context.Context, d theauth.DeviceCode) error {
	req, err := encodeList(d.RequestedAbilities)
	if err != nil {
		return fmt.Errorf("mysql: insert device code: %w", err)
	}
	app, err := encodeList(d.ApprovedAbilities)
	if err != nil {
		return fmt.Errorf("mysql: insert device code: %w", err)
	}
	created := d.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO device_codes (`+deviceCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(d.ID), d.DeviceCodeHash, d.UserCode, d.Status, d.ClientName, req, app, ulidPtrToBytes(d.ApproverID),
		d.RequesterIP, d.RequesterUA, d.IntervalSeconds, timePtrToNull(d.LastPolledAt), timeUTC(created), timeUTC(d.ExpiresAt))
	if err != nil {
		if isMySQL1062(err) && strings.Contains(err.Error(), "uq_device_codes_user_code") {
			return theauth.ErrDeviceUserCodeTaken
		}
		return fmt.Errorf("mysql: insert device code: %w", err)
	}
	return nil
}

// DeviceCodeByUserCode returns the request with the given user code, else ErrNotFound.
func (s *Store) DeviceCodeByUserCode(ctx context.Context, userCode string) (*theauth.DeviceCode, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM device_codes WHERE user_code = ?`, userCode))
	if err != nil {
		return nil, notFoundOr("device code by user code", err)
	}
	return &d, nil
}

// DeviceCodeByHash returns the request with the given device code hash, else ErrNotFound.
func (s *Store) DeviceCodeByHash(ctx context.Context, hash []byte) (*theauth.DeviceCode, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM device_codes WHERE device_code_hash = ?`, hash))
	if err != nil {
		return nil, notFoundOr("device code by hash", err)
	}
	return &d, nil
}

// DecideDeviceCode moves a pending, unexpired request to approved or denied in one conditional update.
func (s *Store) DecideDeviceCode(ctx context.Context, userCode string, d theauth.DeviceDecision, now time.Time) error {
	status, abilities := theauth.DeviceStatusDenied, "[]"
	if d.Approve {
		status = theauth.DeviceStatusApproved
		var err error
		if abilities, err = encodeList(d.Abilities); err != nil {
			return fmt.Errorf("mysql: decide device code: %w", err)
		}
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE device_codes SET status = ?, approved_abilities = ?, approver_id = ?
WHERE user_code = ? AND status = ? AND expires_at > ?`,
		status, abilities, ulidToBytes(d.ApproverID), userCode, theauth.DeviceStatusPending, timeUTC(now))
	if err != nil {
		return fmt.Errorf("mysql: decide device code: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("mysql: decide device code: %w", storage.ErrNotFound)
	}
	return nil
}

// ClaimDeviceCode atomically moves an approved, unexpired request to redeemed; one concurrent caller wins.
func (s *Store) ClaimDeviceCode(ctx context.Context, hash []byte, now time.Time) (*theauth.DeviceCode, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mysql: claim device code: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
UPDATE device_codes SET status = ? WHERE device_code_hash = ? AND status = ? AND expires_at > ?`,
		theauth.DeviceStatusRedeemed, hash, theauth.DeviceStatusApproved, timeUTC(now))
	if err != nil {
		return nil, fmt.Errorf("mysql: claim device code: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, fmt.Errorf("mysql: claim device code: %w", storage.ErrNotFound)
	}
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM device_codes WHERE device_code_hash = ?`, hash))
	if err != nil {
		return nil, notFoundOr("claim device code", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("mysql: claim device code: %w", err)
	}
	return &d, nil
}

// RecordDevicePoll stores the last poll time and the current polling interval.
func (s *Store) RecordDevicePoll(ctx context.Context, hash []byte, at time.Time, intervalSeconds int) error {
	res, err := s.db.ExecContext(ctx, `UPDATE device_codes SET last_polled_at = ?, interval_seconds = ? WHERE device_code_hash = ?`,
		timeUTC(at), intervalSeconds, hash)
	if err != nil {
		return fmt.Errorf("mysql: record device poll: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var one int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM device_codes WHERE device_code_hash = ?`, hash).Scan(&one); err != nil {
		return notFoundOr("record device poll", err)
	}
	return nil
}

// DeleteExpiredDeviceCodes removes requests that expired before the cutoff.
func (s *Store) DeleteExpiredDeviceCodes(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM device_codes WHERE expires_at < ?`, timeUTC(before))
	return rowsCount("delete expired device codes", res, err)
}

// ListPendingDeviceCodes returns pending, unexpired requests newest first without device code hashes.
func (s *Store) ListPendingDeviceCodes(ctx context.Context, f theauth.DevicePendingFilter) ([]theauth.DeviceCode, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceCols+` FROM device_codes
WHERE status = ? AND expires_at > ? ORDER BY created_at DESC, id DESC LIMIT ?`,
		theauth.DeviceStatusPending, timeUTC(f.Now), limit)
	if err != nil {
		return nil, fmt.Errorf("mysql: list pending device codes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.DeviceCode
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("mysql: scan pending device code: %w", err)
		}
		d.DeviceCodeHash = nil
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mysql: list pending device codes: %w", err)
	}
	return out, nil
}
