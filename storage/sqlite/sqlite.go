package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/oklog/ulid/v2"
)

// DefaultTablePrefix is the table name prefix used when WithTablePrefix is not set.
const DefaultTablePrefix = "theauth_"

var prefixPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var (
	_ theauth.CoreStorage         = (*Store)(nil)
	_ theauth.OAuthAccountStorage = (*Store)(nil)
	_ theauth.WebAuthnStorage     = (*Store)(nil)
	_ theauth.TOTPStorage         = (*Store)(nil)
	_ theauth.AuditStorage        = (*Store)(nil)
)

type config struct {
	prefix      string
	allowFKsOff bool
}

// Option configures New and Migrate.
type Option func(*config) error

// WithTablePrefix sets the table name prefix, which must match between Migrate and New.
func WithTablePrefix(prefix string) Option {
	return func(c *config) error {
		if !prefixPattern.MatchString(prefix) {
			return fmt.Errorf("theauth sqlite: invalid table prefix %q", prefix)
		}
		c.prefix = prefix
		return nil
	}
}

// AllowForeignKeysOff lets New succeed when PRAGMA foreign_keys is off, which disables ON DELETE CASCADE.
func AllowForeignKeysOff() Option {
	return func(c *config) error {
		c.allowFKsOff = true
		return nil
	}
}

func buildConfig(opts []Option) (config, error) {
	c := config{prefix: DefaultTablePrefix}
	for _, o := range opts {
		if err := o(&c); err != nil {
			return config{}, err
		}
	}
	return c, nil
}

// DBTX is the subset of *sql.DB and *sql.Tx the Store runs its statements on.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

// Store is the SQLite-backed storage adapter.
type Store struct {
	db     DBTX
	prefix string
	cache  sync.Map
	// Bound to a caller's transaction: multi-statement methods use savepoints, never BeginTx.
	inCallerTx bool
	savepoints atomic.Uint64
}

// New wraps db, which the caller keeps ownership of, and verifies foreign keys are enforced.
func New(db *sql.DB, opts ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("theauth sqlite: nil *sql.DB")
	}
	c, err := buildConfig(opts)
	if err != nil {
		return nil, err
	}
	if err := checkForeignKeys(db, c); err != nil {
		return nil, err
	}
	return &Store{db: db, prefix: c.prefix}, nil
}

// NewTx binds a Store to the caller's open transaction so every method runs on it.
//
// Nothing is committed or rolled back by the Store: the caller owns tx and must
// stop using the Store once tx ends. Multi-statement methods use SAVEPOINTs
// inside tx. Run Migrate on the *sql.DB beforehand; it cannot run inside a Tx.
func NewTx(tx *sql.Tx, opts ...Option) (*Store, error) {
	if tx == nil {
		return nil, errors.New("theauth sqlite: nil *sql.Tx")
	}
	c, err := buildConfig(opts)
	if err != nil {
		return nil, err
	}
	if err := checkForeignKeys(tx, c); err != nil {
		return nil, err
	}
	return &Store{db: tx, prefix: c.prefix, inCallerTx: true}, nil
}

func checkForeignKeys(db DBTX, c config) error {
	if c.allowFKsOff {
		return nil
	}
	var on int
	if err := db.QueryRowContext(context.Background(), `PRAGMA foreign_keys`).Scan(&on); err != nil {
		return fmt.Errorf("theauth sqlite: read foreign_keys pragma: %w", err)
	}
	if on != 1 {
		return errors.New("theauth sqlite: PRAGMA foreign_keys is off; add _pragma=foreign_keys(1) to the DSN or pass AllowForeignKeysOff")
	}
	return nil
}

// q rewrites the default table prefix in a query to the configured one.
func (s *Store) q(query string) string {
	if s.prefix == DefaultTablePrefix {
		return query
	}
	if v, ok := s.cache.Load(query); ok {
		return v.(string)
	}
	out := strings.ReplaceAll(query, DefaultTablePrefix, s.prefix)
	s.cache.Store(query, out)
	return out
}

func (s *Store) inTx(ctx context.Context, op string, fn func(tx DBTX) error) error {
	if s.inCallerTx {
		return s.inSavepoint(ctx, op, fn)
	}
	db, ok := s.db.(*sql.DB)
	if !ok {
		return fmt.Errorf("theauth sqlite: %s: unsupported DBTX %T", op, s.db)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("theauth sqlite: %s: begin: %w", op, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return fmt.Errorf("theauth sqlite: %s: %w", op, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("theauth sqlite: %s: commit: %w", op, err)
	}
	return nil
}

func (s *Store) inSavepoint(ctx context.Context, op string, fn func(tx DBTX) error) error {
	name := fmt.Sprintf("theauth_sp_%d", s.savepoints.Add(1))
	if _, err := s.db.ExecContext(ctx, `SAVEPOINT `+name); err != nil {
		return fmt.Errorf("theauth sqlite: %s: savepoint: %w", op, err)
	}
	if err := fn(s.db); err != nil {
		bg := context.WithoutCancel(ctx)
		_, _ = s.db.ExecContext(bg, `ROLLBACK TO `+name)
		_, _ = s.db.ExecContext(bg, `RELEASE `+name)
		return fmt.Errorf("theauth sqlite: %s: %w", op, err)
	}
	if _, err := s.db.ExecContext(ctx, `RELEASE `+name); err != nil {
		return fmt.Errorf("theauth sqlite: %s: release savepoint: %w", op, err)
	}
	return nil
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("theauth sqlite: %s: %w", op, err)
}

func notFoundOr(op string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("theauth sqlite: %s: %w", op, theauth.ErrStorageNotFound)
	}
	return wrap(op, err)
}

func requireRows(op string, res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return wrap(op, err)
	}
	if n == 0 {
		return fmt.Errorf("theauth sqlite: %s: %w", op, theauth.ErrStorageNotFound)
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func idStr(id theauth.ULID) string { return id.String() }

func idPtrStr(id *theauth.ULID) sql.NullString {
	if id == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: id.String(), Valid: true}
}

func parseID(s string) (theauth.ULID, error) {
	id, err := ulid.Parse(s)
	if err != nil {
		return theauth.ULID{}, fmt.Errorf("parse stored id %q: %w", s, err)
	}
	return id, nil
}

func parseIDPtr(ns sql.NullString) (*theauth.ULID, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil
	}
	id, err := parseID(ns.String)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func toMicro(t time.Time) int64 { return t.UTC().UnixMicro() }

func fromMicro(v int64) time.Time { return time.UnixMicro(v).UTC() }

func toNullMicro(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: toMicro(*t), Valid: true}
}

func fromNullMicro(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := fromMicro(n.Int64)
	return &t
}

func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func orNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now()
	}
	return t
}
