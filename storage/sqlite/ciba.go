package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
)

var _ theauth.CIBAStorage = (*Store)(nil)

// Extra CIBA lifecycle states persisted by this store beyond the three the
// service layer writes (pending, approved, denied).
const (
	// BackchannelStatusConsumed marks an approved request whose tokens were
	// redeemed through RedeemBackchannelRequest.
	BackchannelStatusConsumed = "consumed"
	// BackchannelStatusExpired marks a pending request swept by
	// ExpireBackchannelRequests.
	BackchannelStatusExpired = "expired"
)

// ErrBackchannelStateConflict is returned by UpdateBackchannelRequest when the
// stored request is no longer pending, so a second approve or deny loses.
var ErrBackchannelStateConflict = errors.New("theauth sqlite: backchannel request is not pending")

const cibaCols = `auth_req_id, client_id, user_id, login_hint, login_hint_token, id_token_hint,
	scope, binding_message, client_notification_token, status, access_token, refresh_token, id_token,
	poll_interval, last_poll_at, expires_at, created_at`

func scanBackchannel(r scanner) (theauth.BackchannelRequest, error) {
	var (
		req              theauth.BackchannelRequest
		user             sql.NullString
		scope            string
		lastPoll         sql.NullInt64
		expires, created int64
	)
	if err := r.Scan(&req.AuthReqID, &req.ClientID, &user, &req.LoginHint, &req.LoginHintToken, &req.IDTokenHint,
		&scope, &req.BindingMessage, &req.ClientNotificationToken, &req.Status, &req.AccessToken,
		&req.RefreshToken, &req.IDToken, &req.PollInterval, &lastPoll, &expires, &created); err != nil {
		return theauth.BackchannelRequest{}, err
	}
	uid, err := parseIDPtr(user)
	if err != nil {
		return theauth.BackchannelRequest{}, err
	}
	req.UserID = uid
	if err := json.Unmarshal([]byte(scope), &req.Scope); err != nil {
		return theauth.BackchannelRequest{}, fmt.Errorf("decode scope: %w", err)
	}
	if len(req.Scope) == 0 {
		req.Scope = nil
	}
	req.LastPollAt = fromNullMicro(lastPoll)
	req.ExpiresAt = fromMicro(expires)
	req.CreatedAt = fromMicro(created)
	return req, nil
}

func encodeScope(scope []string) (string, error) {
	if scope == nil {
		scope = []string{}
	}
	b, err := json.Marshal(scope)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// InsertBackchannelRequest fails on a duplicate auth_req_id (primary key).
func (s *Store) InsertBackchannelRequest(ctx context.Context, req theauth.BackchannelRequest) error {
	scope, err := encodeScope(req.Scope)
	if err != nil {
		return wrap("insert backchannel request", err)
	}
	status := req.Status
	if status == "" {
		status = theauth.BackchannelStatusPending
	}
	_, err = s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_backchannel_requests (
	auth_req_id, client_id, user_id, login_hint, login_hint_token, id_token_hint, scope,
	binding_message, client_notification_token, status, poll_interval, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		req.AuthReqID, req.ClientID, idPtrStr(req.UserID), req.LoginHint, req.LoginHintToken, req.IDTokenHint,
		scope, req.BindingMessage, req.ClientNotificationToken, status, req.PollInterval,
		toMicro(req.ExpiresAt), toMicro(orNow(req.CreatedAt)))
	return wrap("insert backchannel request", err)
}

func (s *Store) BackchannelRequestByID(ctx context.Context, authReqID string) (theauth.BackchannelRequest, error) {
	req, err := scanBackchannel(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+cibaCols+` FROM theauth_backchannel_requests WHERE auth_req_id = ?`), authReqID))
	if err != nil {
		return theauth.BackchannelRequest{}, notFoundOr("backchannel request by id", err)
	}
	return req, nil
}

// UpdateBackchannelRequest implements theauth.CIBAStorage. Mutable fields are written only
// while the row is still pending, in one conditional UPDATE, so approval or denial happens
// exactly once under concurrency.
func (s *Store) UpdateBackchannelRequest(ctx context.Context, req theauth.BackchannelRequest) error {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_backchannel_requests SET
	user_id = ?, status = ?, access_token = ?, refresh_token = ?, id_token = ?,
	poll_interval = ?, last_poll_at = ?
WHERE auth_req_id = ? AND status = 'pending'`),
		idPtrStr(req.UserID), req.Status, req.AccessToken, req.RefreshToken, req.IDToken,
		req.PollInterval, toNullMicro(req.LastPollAt), req.AuthReqID)
	if err != nil {
		return wrap("update backchannel request", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrap("update backchannel request", err)
	}
	if n == 1 {
		return nil
	}
	var one int
	switch qerr := s.db.QueryRowContext(ctx,
		s.q(`SELECT 1 FROM theauth_backchannel_requests WHERE auth_req_id = ?`), req.AuthReqID).Scan(&one); {
	case errors.Is(qerr, sql.ErrNoRows):
		return fmt.Errorf("theauth sqlite: update backchannel request: %w", theauth.ErrStorageNotFound)
	case qerr != nil:
		return wrap("update backchannel request", qerr)
	}
	return fmt.Errorf("update backchannel request: %w", ErrBackchannelStateConflict)
}

func (s *Store) DeleteBackchannelRequest(ctx context.Context, authReqID string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM theauth_backchannel_requests WHERE auth_req_id = ?`), authReqID)
	if err != nil {
		return wrap("delete backchannel request", err)
	}
	return requireRows("delete backchannel request", res)
}

// TouchBackchannelPoll implements theauth.CIBAStorage in one UPDATE ... RETURNING.
func (s *Store) TouchBackchannelPoll(ctx context.Context, authReqID string, now time.Time, newInterval int) (theauth.BackchannelRequest, error) {
	req, err := scanBackchannel(s.db.QueryRowContext(ctx, s.q(`
UPDATE theauth_backchannel_requests SET last_poll_at = ?, poll_interval = ?
WHERE auth_req_id = ?
RETURNING `+cibaCols), toMicro(now), newInterval, authReqID))
	if err != nil {
		return theauth.BackchannelRequest{}, notFoundOr("touch backchannel poll", err)
	}
	return req, nil
}

// RedeemBackchannelRequest moves an approved, unexpired request to consumed in one
// statement, so exactly one concurrent caller wins. It extends theauth.CIBAStorage for
// one-time token delivery.
func (s *Store) RedeemBackchannelRequest(ctx context.Context, authReqID string, now time.Time) (theauth.BackchannelRequest, bool, error) {
	req, err := scanBackchannel(s.db.QueryRowContext(ctx, s.q(`
UPDATE theauth_backchannel_requests SET status = 'consumed'
WHERE auth_req_id = ? AND status = 'approved' AND expires_at > ?
RETURNING `+cibaCols), authReqID, toMicro(now)))
	if errors.Is(err, sql.ErrNoRows) {
		return theauth.BackchannelRequest{}, false, nil
	}
	if err != nil {
		return theauth.BackchannelRequest{}, false, wrap("redeem backchannel request", err)
	}
	return req, true, nil
}

// ExpireBackchannelRequests marks every pending request whose deadline has
// passed as expired and returns how many rows changed.
func (s *Store) ExpireBackchannelRequests(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_backchannel_requests SET status = 'expired'
WHERE status = 'pending' AND expires_at <= ?`), toMicro(now))
	if err != nil {
		return 0, wrap("expire backchannel requests", err)
	}
	n, err := res.RowsAffected()
	return n, wrap("expire backchannel requests", err)
}
