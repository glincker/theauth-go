// Package sqlkv implements kv.Cache on a single table of the SQL database you
// already run for theauth storage. It works on Postgres, MySQL and SQLite.
//
// Build the full set of shared stores with kv.FromCache(store). Create the
// table once with EnsureSchema (idempotent) or run Schema(dialect) in your own
// migration tool.
package sqlkv

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Dialect selects the SQL flavor.
type Dialect int

// Supported dialects.
const (
	Postgres Dialect = iota
	MySQL
	SQLite
)

// DefaultTable is the table name used when none is given.
const DefaultTable = "theauth_kv"

// Option tunes New.
type Option func(*Store)

// WithTable overrides the table name. The name is validated as a plain
// identifier because it is interpolated into SQL.
func WithTable(name string) Option { return func(s *Store) { s.table = name } }

// WithClock injects the time source (tests).
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

// Store implements kv.Cache over database/sql.
type Store struct {
	db      *sql.DB
	dialect Dialect
	table   string
	now     func() time.Time
	writes  atomic.Uint64
}

// New returns a Store. It does not touch the database; call EnsureSchema.
func New(db *sql.DB, dialect Dialect, opts ...Option) (*Store, error) {
	s := &Store{db: db, dialect: dialect, table: DefaultTable, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	if !validIdent(s.table) {
		return nil, fmt.Errorf("sqlkv: invalid table name %q", s.table)
	}
	return s, nil
}

func validIdent(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// Schema returns the DDL for the given dialect and table.
func Schema(d Dialect, table string) string {
	blob := "BLOB"
	if d == Postgres {
		blob = "BYTEA"
	}
	key := "TEXT"
	if d == MySQL {
		key = "VARCHAR(255)"
	}
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %[1]s (
  k %[2]s NOT NULL PRIMARY KEY,
  v %[3]s NOT NULL,
  n BIGINT NOT NULL DEFAULT 0,
  expires_at BIGINT NOT NULL
)`, table, key, blob)
}

// EnsureSchema creates the table and its expiry index when missing.
func (s *Store) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, Schema(s.dialect, s.table)); err != nil {
		return err
	}
	idx := fmt.Sprintf("CREATE INDEX idx_%[1]s_expires ON %[1]s (expires_at)", s.table)
	if s.dialect != MySQL {
		idx = strings.Replace(idx, "CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1)
	}
	if _, err := s.db.ExecContext(ctx, idx); err != nil {
		// MySQL has no IF NOT EXISTS for indexes; a duplicate-index error on a
		// re-run is expected and harmless.
		if s.dialect == MySQL && strings.Contains(err.Error(), "Duplicate key name") {
			return nil
		}
		return err
	}
	return nil
}

// never is the expires_at sentinel for entries without a TTL.
const never = int64(1) << 62

func (s *Store) expiry(ttl time.Duration) int64 {
	if ttl <= 0 {
		return never
	}
	return s.now().Add(ttl).UnixMilli()
}

// q rewrites ? placeholders to $n for Postgres.
func (s *Store) q(query string) string {
	if s.dialect != Postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *Store) maybePrune(ctx context.Context) {
	if s.writes.Add(1)%256 != 0 {
		return
	}
	_, _ = s.Prune(ctx)
}

// Prune deletes expired rows and returns how many it removed. Writes call it
// opportunistically; call it from a timer if the table sees little traffic.
func (s *Store) Prune(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.q("DELETE FROM "+s.table+" WHERE expires_at <= ?"), s.now().UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Get implements kv.Cache.
func (s *Store) Get(ctx context.Context, key string) ([]byte, bool, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx,
		s.q("SELECT v FROM "+s.table+" WHERE k = ? AND expires_at > ?"), key, s.now().UnixMilli()).Scan(&v)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return v, true, nil
}

// Set implements kv.Cache.
func (s *Store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if value == nil {
		value = []byte{}
	}
	var query string
	if s.dialect == MySQL {
		query = "INSERT INTO " + s.table + " (k, v, n, expires_at) VALUES (?, ?, 0, ?) " +
			"ON DUPLICATE KEY UPDATE v = VALUES(v), n = 0, expires_at = VALUES(expires_at)"
	} else {
		query = "INSERT INTO " + s.table + " (k, v, n, expires_at) VALUES (?, ?, 0, ?) " +
			"ON CONFLICT (k) DO UPDATE SET v = excluded.v, n = 0, expires_at = excluded.expires_at"
	}
	_, err := s.db.ExecContext(ctx, s.q(query), key, value, s.expiry(ttl))
	if err == nil {
		s.maybePrune(ctx)
	}
	return err
}

// SetNX implements kv.Cache.
func (s *Store) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if value == nil {
		value = []byte{}
	}
	// Clear an expired holder first so it does not block the insert.
	if _, err := s.db.ExecContext(ctx, s.q("DELETE FROM "+s.table+" WHERE k = ? AND expires_at <= ?"),
		key, s.now().UnixMilli()); err != nil {
		return false, err
	}
	verb, tail := "INSERT", " ON CONFLICT (k) DO NOTHING"
	if s.dialect == MySQL {
		verb, tail = "INSERT IGNORE", ""
	}
	res, err := s.db.ExecContext(ctx,
		s.q(verb+" INTO "+s.table+" (k, v, n, expires_at) VALUES (?, ?, 0, ?)"+tail), key, value, s.expiry(ttl))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	s.maybePrune(ctx)
	return n == 1, nil
}

// Delete implements kv.Cache.
func (s *Store) Delete(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, s.q("DELETE FROM "+s.table+" WHERE k = ?"), key)
	return err
}

// Incr implements kv.Cache.
func (s *Store) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	now := s.now().UnixMilli()
	exp := s.expiry(ttl)
	defer s.maybePrune(ctx)
	if s.dialect == MySQL {
		return s.incrMySQL(ctx, key, now, exp)
	}
	var n int64
	err := s.db.QueryRowContext(ctx, s.q(`INSERT INTO `+s.table+` AS t (k, v, n, expires_at) VALUES (?, ?, 1, ?)
ON CONFLICT (k) DO UPDATE SET
  n = CASE WHEN t.expires_at <= ? THEN 1 ELSE t.n + 1 END,
  expires_at = CASE WHEN t.expires_at <= ? THEN ? ELSE t.expires_at END
RETURNING n`), key, []byte{}, exp, now, now, exp).Scan(&n)
	return n, err
}

func (s *Store) incrMySQL(ctx context.Context, key string, now, exp int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	// Assignments run left to right, so the expires_at test in the n
	// assignment still sees the old value.
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+s.table+" (k, v, n, expires_at) VALUES (?, ?, 1, ?) "+
		"ON DUPLICATE KEY UPDATE n = IF(expires_at <= ?, 1, n + 1), expires_at = IF(expires_at <= ?, ?, expires_at)",
		key, []byte{}, exp, now, now, exp); err != nil {
		return 0, err
	}
	var n int64
	if err := tx.QueryRowContext(ctx, "SELECT n FROM "+s.table+" WHERE k = ?", key).Scan(&n); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}
