package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// postgres_ciba.go: Postgres adapter for the CIBA backchannel_requests table
// introduced by migration 0016. Satisfies the CIBAStorage interface so the
// /oauth/bc-authorize endpoint is automatically enabled when this store is
// used with Config.AuthorizationServer.CIBA != nil.

// InsertBackchannelRequest satisfies CIBAStorage.
func (s *Store) InsertBackchannelRequest(ctx context.Context, req theauth.BackchannelRequest) error {
	const q = `
INSERT INTO backchannel_requests (
  auth_req_id, client_id, user_id,
  login_hint, login_hint_token, id_token_hint,
  scope, binding_message, client_notification_token,
  status, poll_interval, expires_at, created_at
) VALUES (
  $1, $2, $3,
  $4, $5, $6,
  $7, $8, $9,
  $10, $11, $12, $13
)`
	now := req.CreatedAt
	if now.IsZero() {
		now = time.Now()
	}
	_, err := s.pool.Exec(ctx, q,
		req.AuthReqID,
		req.ClientID,
		ulidPtrToPgUUID(req.UserID),
		req.LoginHint,
		req.LoginHintToken,
		req.IDTokenHint,
		emptyIfNilStrings(req.Scope),
		req.BindingMessage,
		req.ClientNotificationToken,
		req.Status,
		req.PollInterval,
		timeToTs(req.ExpiresAt),
		timeToTs(now),
	)
	return err
}

// BackchannelRequestByID satisfies CIBAStorage.
func (s *Store) BackchannelRequestByID(ctx context.Context, authReqID string) (theauth.BackchannelRequest, error) {
	const q = `
SELECT
  auth_req_id, client_id, user_id,
  login_hint, login_hint_token, id_token_hint,
  scope, binding_message, client_notification_token,
  status, access_token, refresh_token, id_token,
  poll_interval, last_poll_at, expires_at, created_at
FROM backchannel_requests
WHERE auth_req_id = $1`
	row := s.pool.QueryRow(ctx, q, authReqID)
	r, err := scanBackchannelRequest(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return theauth.BackchannelRequest{}, storage.ErrNotFound
		}
		return theauth.BackchannelRequest{}, err
	}
	return r, nil
}

// UpdateBackchannelRequest satisfies CIBAStorage. Writes all mutable fields.
func (s *Store) UpdateBackchannelRequest(ctx context.Context, req theauth.BackchannelRequest) error {
	const q = `
UPDATE backchannel_requests SET
  user_id         = $2,
  status          = $3,
  access_token    = $4,
  refresh_token   = $5,
  id_token        = $6,
  poll_interval   = $7,
  last_poll_at    = $8
WHERE auth_req_id = $1`
	tag, err := s.pool.Exec(ctx, q,
		req.AuthReqID,
		ulidPtrToPgUUID(req.UserID),
		req.Status,
		req.AccessToken,
		req.RefreshToken,
		req.IDToken,
		req.PollInterval,
		timePtrToTs(req.LastPollAt),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteBackchannelRequest satisfies CIBAStorage.
func (s *Store) DeleteBackchannelRequest(ctx context.Context, authReqID string) error {
	const q = `DELETE FROM backchannel_requests WHERE auth_req_id = $1`
	tag, err := s.pool.Exec(ctx, q, authReqID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// TouchBackchannelPoll satisfies CIBAStorage. Updates last_poll_at and
// poll_interval atomically and returns the updated row.
func (s *Store) TouchBackchannelPoll(ctx context.Context, authReqID string, now time.Time, newInterval int) (theauth.BackchannelRequest, error) {
	const q = `
UPDATE backchannel_requests SET
  last_poll_at  = $2,
  poll_interval = $3
WHERE auth_req_id = $1
RETURNING
  auth_req_id, client_id, user_id,
  login_hint, login_hint_token, id_token_hint,
  scope, binding_message, client_notification_token,
  status, access_token, refresh_token, id_token,
  poll_interval, last_poll_at, expires_at, created_at`
	row := s.pool.QueryRow(ctx, q, authReqID, timeToTs(now), newInterval)
	r, err := scanBackchannelRequest(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return theauth.BackchannelRequest{}, storage.ErrNotFound
		}
		return theauth.BackchannelRequest{}, err
	}
	return r, nil
}

// ---------- scan helper ----------

func scanBackchannelRequest(row pgRowScanner) (theauth.BackchannelRequest, error) {
	var (
		authReqID, clientID       string
		userID                    pgtype.UUID
		loginHint, loginHintToken string
		idTokenHint, bindingMsg   string
		clientNotifToken, status  string
		accessToken, refreshToken string
		idToken                   string
		scope                     []string
		pollInterval              int
		lastPollAt                pgtype.Timestamptz
		expiresAt, createdAt      pgtype.Timestamptz
	)
	if err := row.Scan(
		&authReqID, &clientID, &userID,
		&loginHint, &loginHintToken, &idTokenHint,
		&scope, &bindingMsg, &clientNotifToken,
		&status, &accessToken, &refreshToken, &idToken,
		&pollInterval, &lastPollAt, &expiresAt, &createdAt,
	); err != nil {
		return theauth.BackchannelRequest{}, err
	}
	return theauth.BackchannelRequest{
		AuthReqID:               authReqID,
		ClientID:                clientID,
		UserID:                  pgUUIDToULIDPtr(userID),
		LoginHint:               loginHint,
		LoginHintToken:          loginHintToken,
		IDTokenHint:             idTokenHint,
		Scope:                   scope,
		BindingMessage:          bindingMsg,
		ClientNotificationToken: clientNotifToken,
		Status:                  status,
		AccessToken:             accessToken,
		RefreshToken:            refreshToken,
		IDToken:                 idToken,
		PollInterval:            pollInterval,
		LastPollAt:              tsToTimePtr(lastPollAt),
		ExpiresAt:               tsToTime(expiresAt),
		CreatedAt:               tsToTime(createdAt),
	}, nil
}
