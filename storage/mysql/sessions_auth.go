package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

// methodsJSONVal encodes the auth methods as a JSON array, or NULL ("no
// record") when empty.
func methodsJSONVal(m []string) any {
	if len(m) == 0 {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return string(b)
}

// authTimeVal maps the zero time to NULL.
func authTimeVal(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return timeUTC(t)
}

// AppendSessionAuthMethods adds methods to the session's auth_methods and
// advances auth_time. The row is locked with SELECT ... FOR UPDATE for the
// read-merge-write, so concurrent appends serialize and none loses methods.
func (s *Store) AppendSessionAuthMethods(ctx context.Context, id theauth.ULID, methods []string, at time.Time) ([]string, time.Time, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("mysql: append session auth methods: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var (
		raw      []byte
		authTime sql.NullTime
	)
	err = tx.QueryRowContext(ctx, `SELECT auth_methods, auth_time FROM sessions WHERE id = ? FOR UPDATE`, ulidToBytes(id)).Scan(&raw, &authTime)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, time.Time{}, fmt.Errorf("mysql: append session auth methods: %w", storage.ErrNotFound)
		}
		return nil, time.Time{}, fmt.Errorf("mysql: append session auth methods: %w", err)
	}
	var cur []string
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cur); err != nil {
			return nil, time.Time{}, fmt.Errorf("mysql: append session auth methods: decode: %w", err)
		}
	}
	merged := theauth.MergeAuthMethods(cur, methods...)
	at = timeUTC(at)
	if authTime.Valid && !at.After(authTime.Time.UTC()) {
		at = authTime.Time.UTC()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET auth_methods = ?, auth_time = ? WHERE id = ?`,
		methodsJSONVal(merged), at, ulidToBytes(id)); err != nil {
		return nil, time.Time{}, fmt.Errorf("mysql: append session auth methods: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, time.Time{}, fmt.Errorf("mysql: append session auth methods: commit: %w", err)
	}
	return merged, at, nil
}
