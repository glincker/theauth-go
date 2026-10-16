package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"
	"time"

	mysqldrv "github.com/go-sql-driver/mysql"

	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage"
)

// fakeDriver reports 0 rows affected for every UPDATE (same value twice) and
// answers the existence probe from the exists flag.
type fakeDriver struct{ exists bool }

type fakeConn struct{ d *fakeDriver }
type fakeStmt struct {
	d     *fakeDriver
	query string
}
type fakeRows struct {
	done bool
}

func (d *fakeDriver) Open(string) (driver.Conn, error) { return &fakeConn{d}, nil }
func (c *fakeConn) Prepare(q string) (driver.Stmt, error) {
	return &fakeStmt{c.d, q}, nil
}
func (c *fakeConn) Close() error              { return nil }
func (c *fakeConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }
func (s *fakeStmt) Close() error              { return nil }
func (s *fakeStmt) NumInput() int             { return -1 }
func (s *fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	return driver.RowsAffected(0), nil
}
func (s *fakeStmt) Query([]driver.Value) (driver.Rows, error) {
	if s.d.exists {
		return &fakeRows{}, nil
	}
	return &fakeRows{done: true}, nil
}
func (r *fakeRows) Columns() []string { return []string{"1"} }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = int64(1)
	return nil
}

var fakeSeq int

func newFakeStore(t *testing.T, exists bool) *Store {
	t.Helper()
	fakeSeq++
	name := "mysqlfake" + time.Now().Format("150405.000000") + string(rune('a'+fakeSeq))
	sql.Register(name, &fakeDriver{exists: exists})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return New(db)
}

func TestSessionUpdatesZeroRowsAffected(t *testing.T) {
	ctx := context.Background()
	id := ulid.New()
	ops := map[string]func(*Store) error{
		"auth level": func(s *Store) error { return s.UpdateSessionAuthLevel(ctx, id, "aal2") },
		"active org": func(s *Store) error { return s.SetSessionActiveOrganization(ctx, id, nil) },
		"revoke":     func(s *Store) error { return s.RevokeSession(ctx, id) },
	}
	tests := []struct {
		name    string
		exists  bool
		wantErr error
	}{
		{"existing session, unchanged value is success", true, nil},
		{"missing session is not found", false, storage.ErrNotFound},
	}
	for opName, op := range ops {
		for _, tc := range tests {
			t.Run(opName+"/"+tc.name, func(t *testing.T) {
				err := op(newFakeStore(t, tc.exists))
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got %v want %v", err, tc.wantErr)
				}
			})
		}
	}
}

func TestRetryDeadlock(t *testing.T) {
	old := deadlockBackoffBase
	deadlockBackoffBase = time.Microsecond
	defer func() { deadlockBackoffBase = old }()
	dl := &mysqldrv.MySQLError{Number: 1213}
	other := errors.New("boom")

	tests := []struct {
		name      string
		errs      []error
		cancelled bool
		wantCalls int
		wantErr   error
	}{
		{"success first try", []error{nil}, false, 1, nil},
		{"deadlock then success", []error{dl, dl, nil}, false, 3, nil},
		{"non deadlock not retried", []error{other}, false, 1, other},
		{"exhausts bounded retries", []error{dl, dl, dl, dl, dl, dl, dl, dl}, false, maxDeadlockRetries + 1, dl},
		{"cancelled ctx stops early", []error{dl}, true, 0, context.Canceled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			calls := 0
			err := retryDeadlock(ctx, func() error {
				e := tc.errs[calls]
				calls++
				return e
			})
			if calls != tc.wantCalls {
				t.Fatalf("calls=%d want %d", calls, tc.wantCalls)
			}
			if !errors.Is(err, tc.wantErr) && (tc.wantErr != dl || !isDeadlock(err)) {
				t.Fatalf("err=%v want %v", err, tc.wantErr)
			}
		})
	}
}

func TestRetryDeadlockCancelDuringBackoff(t *testing.T) {
	old := deadlockBackoffBase
	deadlockBackoffBase = time.Hour
	defer func() { deadlockBackoffBase = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := retryDeadlock(ctx, func() error { return &mysqldrv.MySQLError{Number: 1213} })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}
