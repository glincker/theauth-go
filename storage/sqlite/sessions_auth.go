package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
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
	return toMicro(t)
}

// AppendSessionAuthMethods adds methods to the session's auth_methods and
// advances auth_time. The first statement of the transaction is a write, so
// SQLite holds the write lock for the whole read-merge-write and concurrent
// appends serialize without losing methods.
func (s *Store) AppendSessionAuthMethods(ctx context.Context, id theauth.ULID, methods []string, at time.Time) ([]string, time.Time, error) {
	var (
		merged []string
		outAt  time.Time
	)
	has, err := s.hasSessionAuthCols(ctx)
	if err != nil {
		return nil, time.Time{}, wrap("append session auth methods", err)
	}
	if !has {
		return nil, time.Time{}, fmt.Errorf("theauth sqlite: append session auth methods: %w: migration 0034 (session auth methods) is not applied", theauth.ErrStorageMissingCapability)
	}
	err = s.inTx(ctx, "append session auth methods", func(tx DBTX) error {
		res, err := tx.ExecContext(ctx, s.q(`UPDATE theauth_sessions SET auth_time = MAX(COALESCE(auth_time, 0), ?) WHERE id = ?`),
			toMicro(at), idStr(id))
		if err != nil {
			return err
		}
		if err := requireRows("append session auth methods", res); err != nil {
			return err
		}
		var (
			raw  sql.NullString
			when sql.NullInt64
		)
		if err := tx.QueryRowContext(ctx, s.q(`SELECT auth_methods, auth_time FROM theauth_sessions WHERE id = ?`), idStr(id)).Scan(&raw, &when); err != nil {
			return err
		}
		var cur []string
		if raw.Valid && raw.String != "" {
			if err := json.Unmarshal([]byte(raw.String), &cur); err != nil {
				return fmt.Errorf("decode: %w", err)
			}
		}
		merged = theauth.MergeAuthMethods(cur, methods...)
		if _, err := tx.ExecContext(ctx, s.q(`UPDATE theauth_sessions SET auth_methods = ? WHERE id = ?`),
			methodsJSONVal(merged), idStr(id)); err != nil {
			return err
		}
		outAt = fromMicro(when.Int64)
		return nil
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return merged, outAt, nil
}
