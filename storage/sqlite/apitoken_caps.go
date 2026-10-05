package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
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

func scanAPIToken(r scanner) (theauth.APIToken, error) {
	var (
		id, owner, kind, name, abilities, hint string
		tokKind, agentName                     string
		hash                                   []byte
		created                                int64
		expires, used, revoked                 sql.NullInt64
		delegated                              sql.NullString
	)
	if err := r.Scan(&id, &owner, &kind, &name, &abilities, &hash, &hint, &created, &expires, &used, &revoked, &tokKind, &agentName, &delegated); err != nil {
		return theauth.APIToken{}, err
	}
	tid, err := parseID(id)
	if err != nil {
		return theauth.APIToken{}, err
	}
	oid, err := parseID(owner)
	if err != nil {
		return theauth.APIToken{}, err
	}
	ab, err := decodeList(abilities)
	if err != nil {
		return theauth.APIToken{}, err
	}
	delegatedBy, err := parseIDPtr(delegated)
	if err != nil {
		return theauth.APIToken{}, err
	}
	return theauth.APIToken{
		ID: tid, OwnerID: oid, OwnerKind: kind, Name: name, Abilities: ab, TokenHash: hash, Hint: hint,
		Kind: tokKind, AgentName: agentName, DelegatedBy: delegatedBy,
		CreatedAt: fromMicro(created), ExpiresAt: fromNullMicro(expires),
		LastUsedAt: fromNullMicro(used), RevokedAt: fromNullMicro(revoked),
	}, nil
}

// InsertAPIToken stores a token and returns the stored row.
func (s *Store) InsertAPIToken(ctx context.Context, t theauth.APIToken) (theauth.APIToken, error) {
	abilities, err := encodeList(t.Abilities)
	if err != nil {
		return theauth.APIToken{}, wrap("insert api token", err)
	}
	out, err := scanAPIToken(s.db.QueryRowContext(ctx, s.q(`
INSERT INTO theauth_api_tokens (id, owner_id, owner_kind, name, abilities, token_hash, hint, created_at, expires_at, last_used_at, revoked_at, kind, agent_name, delegated_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING `+apiTokenCols),
		idStr(t.ID), idStr(t.OwnerID), t.OwnerKind, t.Name, abilities, t.TokenHash, t.Hint,
		toMicro(orNow(t.CreatedAt)), toNullMicro(t.ExpiresAt), toNullMicro(t.LastUsedAt), toNullMicro(t.RevokedAt),
		t.Kind, t.AgentName, idPtrStr(t.DelegatedBy)))
	if err != nil {
		return theauth.APIToken{}, wrap("insert api token", err)
	}
	return out, nil
}

// APITokenByHash returns the token with the given secret hash, else ErrStorageNotFound.
func (s *Store) APITokenByHash(ctx context.Context, hash []byte) (*theauth.APIToken, error) {
	t, err := scanAPIToken(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+apiTokenCols+` FROM theauth_api_tokens WHERE token_hash = ?`), hash))
	if err != nil {
		return nil, notFoundOr("api token by hash", err)
	}
	return &t, nil
}

// APITokenByID returns the token with the given ID, else ErrStorageNotFound.
func (s *Store) APITokenByID(ctx context.Context, id theauth.ULID) (*theauth.APIToken, error) {
	t, err := scanAPIToken(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+apiTokenCols+` FROM theauth_api_tokens WHERE id = ?`), idStr(id)))
	if err != nil {
		return nil, notFoundOr("api token by id", err)
	}
	return &t, nil
}

func (s *Store) queryAPITokens(ctx context.Context, op, where string, args ...any) ([]theauth.APIToken, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+apiTokenCols+` FROM theauth_api_tokens `+where+
		` ORDER BY created_at DESC, id DESC`), args...)
	if err != nil {
		return nil, wrap(op, err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.APIToken{}
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, wrap(op, err)
		}
		out = append(out, t)
	}
	return out, wrap(op, rows.Err())
}

// APITokensByOwner returns every token of the owner, newest first.
func (s *Store) APITokensByOwner(ctx context.Context, ownerID theauth.ULID) ([]theauth.APIToken, error) {
	return s.queryAPITokens(ctx, "api tokens by owner", `WHERE owner_id = ?`, idStr(ownerID))
}

// ListAPITokens returns every token, newest first.
func (s *Store) ListAPITokens(ctx context.Context) ([]theauth.APIToken, error) {
	return s.queryAPITokens(ctx, "list api tokens", ``)
}

// RevokeAPIToken revokes a token, keeping the first revocation time on repeat calls.
func (s *Store) RevokeAPIToken(ctx context.Context, id theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(
		`UPDATE theauth_api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`), toMicro(at), idStr(id))
	if err != nil {
		return wrap("revoke api token", err)
	}
	return requireRows("revoke api token", res)
}

// RevokeAPITokensByOwner revokes the owner's live tokens and returns how many it changed.
func (s *Store) RevokeAPITokensByOwner(ctx context.Context, ownerID theauth.ULID, at time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, s.q(
		`UPDATE theauth_api_tokens SET revoked_at = ? WHERE owner_id = ? AND revoked_at IS NULL`), toMicro(at), idStr(ownerID))
	return rowsOrErr("revoke api tokens by owner", res, err)
}

// TouchAPITokenLastUsed records the last use time of a token.
func (s *Store) TouchAPITokenLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(
		`UPDATE theauth_api_tokens SET last_used_at = ? WHERE id = ?`), toMicro(at), idStr(id))
	if err != nil {
		return wrap("touch api token", err)
	}
	return requireRows("touch api token", res)
}

func scanDevice(r scanner) (theauth.DeviceCode, error) {
	var (
		id, userCode, status, client, reqAb, appAb, ip, ua string
		hash                                               []byte
		approver                                           sql.NullString
		interval                                           int
		created, expires                                   int64
		polled                                             sql.NullInt64
	)
	if err := r.Scan(&id, &hash, &userCode, &status, &client, &reqAb, &appAb, &approver, &ip, &ua,
		&interval, &polled, &created, &expires); err != nil {
		return theauth.DeviceCode{}, err
	}
	did, err := parseID(id)
	if err != nil {
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
	aid, err := parseIDPtr(approver)
	if err != nil {
		return theauth.DeviceCode{}, err
	}
	return theauth.DeviceCode{
		ID: did, DeviceCodeHash: hash, UserCode: userCode, Status: status, ClientName: client,
		RequestedAbilities: req, ApprovedAbilities: app, ApproverID: aid, RequesterIP: ip, RequesterUA: ua,
		IntervalSeconds: interval, LastPolledAt: fromNullMicro(polled),
		CreatedAt: fromMicro(created), ExpiresAt: fromMicro(expires),
	}, nil
}

// InsertDeviceCode stores a request, returning ErrDeviceUserCodeTaken on a user code collision.
func (s *Store) InsertDeviceCode(ctx context.Context, d theauth.DeviceCode) error {
	req, err := encodeList(d.RequestedAbilities)
	if err != nil {
		return wrap("insert device code", err)
	}
	app, err := encodeList(d.ApprovedAbilities)
	if err != nil {
		return wrap("insert device code", err)
	}
	_, err = s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_device_codes (`+deviceCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		idStr(d.ID), d.DeviceCodeHash, d.UserCode, d.Status, d.ClientName, req, app, idPtrStr(d.ApproverID),
		d.RequesterIP, d.RequesterUA, d.IntervalSeconds, toNullMicro(d.LastPolledAt),
		toMicro(orNow(d.CreatedAt)), toMicro(d.ExpiresAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") && strings.Contains(err.Error(), "user_code") {
			return theauth.ErrDeviceUserCodeTaken
		}
		return wrap("insert device code", err)
	}
	return nil
}

// DeviceCodeByUserCode returns the request with the given user code, else ErrStorageNotFound.
func (s *Store) DeviceCodeByUserCode(ctx context.Context, userCode string) (*theauth.DeviceCode, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+deviceCols+` FROM theauth_device_codes WHERE user_code = ?`), userCode))
	if err != nil {
		return nil, notFoundOr("device code by user code", err)
	}
	return &d, nil
}

// DeviceCodeByHash returns the request with the given device code hash, else ErrStorageNotFound.
func (s *Store) DeviceCodeByHash(ctx context.Context, hash []byte) (*theauth.DeviceCode, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+deviceCols+` FROM theauth_device_codes WHERE device_code_hash = ?`), hash))
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
			return wrap("decide device code", err)
		}
	}
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_device_codes SET status = ?, approved_abilities = ?, approver_id = ?
WHERE user_code = ? AND status = ? AND expires_at > ?`),
		status, abilities, idStr(d.ApproverID), userCode, theauth.DeviceStatusPending, toMicro(now))
	if err != nil {
		return wrap("decide device code", err)
	}
	return requireRows("decide device code", res)
}

// ClaimDeviceCode atomically moves an approved, unexpired request to redeemed; one concurrent caller wins.
func (s *Store) ClaimDeviceCode(ctx context.Context, hash []byte, now time.Time) (*theauth.DeviceCode, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx, s.q(`
UPDATE theauth_device_codes SET status = ?
WHERE device_code_hash = ? AND status = ? AND expires_at > ?
RETURNING `+deviceCols), theauth.DeviceStatusRedeemed, hash, theauth.DeviceStatusApproved, toMicro(now)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("theauth sqlite: claim device code: %w", theauth.ErrStorageNotFound)
		}
		return nil, wrap("claim device code", err)
	}
	return &d, nil
}

// RecordDevicePoll stores the last poll time and the current polling interval.
func (s *Store) RecordDevicePoll(ctx context.Context, hash []byte, at time.Time, intervalSeconds int) error {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_device_codes SET last_polled_at = ?, interval_seconds = ? WHERE device_code_hash = ?`),
		toMicro(at), intervalSeconds, hash)
	if err != nil {
		return wrap("record device poll", err)
	}
	return requireRows("record device poll", res)
}

// DeleteExpiredDeviceCodes removes requests that expired before the cutoff.
func (s *Store) DeleteExpiredDeviceCodes(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM theauth_device_codes WHERE expires_at < ?`), toMicro(before))
	return rowsOrErr("delete expired device codes", res, err)
}

// ListPendingDeviceCodes returns pending, unexpired requests newest first without device code hashes.
func (s *Store) ListPendingDeviceCodes(ctx context.Context, f theauth.DevicePendingFilter) ([]theauth.DeviceCode, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+deviceCols+` FROM theauth_device_codes
WHERE status = ? AND expires_at > ? ORDER BY created_at DESC, id DESC LIMIT ?`),
		theauth.DeviceStatusPending, toMicro(f.Now), pendingLimit(f.Limit))
	if err != nil {
		return nil, wrap("list pending device codes", err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.DeviceCode
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, wrap("scan pending device code", err)
		}
		d.DeviceCodeHash = nil
		out = append(out, d)
	}
	return out, wrap("list pending device codes", rows.Err())
}

func pendingLimit(n int) int {
	if n <= 0 {
		return 100
	}
	return n
}
