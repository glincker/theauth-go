package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storagetest"
	_ "modernc.org/sqlite"
)

const pragmas = "?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate"

// TestMain warms the modernc driver up with a serial open; the first parallel
// opens otherwise race on its one-time initialization.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "theauth-sqlite-warmup")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "warm.db")+pragmas)
	if err == nil {
		err = db.Ping()
		_ = db.Close()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "auth.db")+pragmas)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// Switching to WAL needs an exclusive lock that concurrent first opens can lose, so do it once serially.
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	return db
}

func newStore(t *testing.T, opts ...sqlitestore.Option) *sqlitestore.Store {
	t.Helper()
	db := openDB(t)
	if err := sqlitestore.Migrate(context.Background(), db, opts...); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := sqlitestore.New(db, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func mkUser(t *testing.T, s *sqlitestore.Store, email string) theauth.User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), theauth.User{ID: ulid.New(), Email: email, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", email, err)
	}
	return u
}

func TestContract(t *testing.T) {
	t.Parallel()
	suites := []struct {
		name string
		run  func(t *testing.T, s *sqlitestore.Store)
	}{
		{"Core", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunCore(t, s) }},
		{"WebAuthn", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunWebAuthn(t, s) }},
		{"TOTP", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunTOTP(t, s) }},
		{"Audit", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunAudit(t, s) }},
	}
	for _, tc := range suites {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, newStore(t))
		})
	}
}

func TestContractCustomPrefix(t *testing.T) {
	t.Parallel()
	s := newStore(t, sqlitestore.WithTablePrefix("auth_x_"))
	storagetest.RunCore(t, s)
}

func TestEmailCaseInsensitive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	u := mkUser(t, s, "Mixed.Case@Example.com")

	for _, q := range []string{"mixed.case@example.com", "MIXED.CASE@EXAMPLE.COM"} {
		got, err := s.UserByEmail(ctx, q)
		if err != nil || got.ID != u.ID {
			t.Fatalf("UserByEmail(%q) = %v, %v", q, got, err)
		}
	}
	if got, _ := s.UserByEmail(ctx, "x"); got != nil {
		t.Fatal("unexpected user")
	}
	if _, err := s.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "MIXED.case@example.COM"}); err == nil {
		t.Fatal("duplicate email differing only by case was accepted")
	}
}

func TestOAuthAccounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	u1 := mkUser(t, s, "o1@example.com")
	u2 := mkUser(t, s, "o2@example.com")
	exp := time.Now().Add(time.Hour)

	a, err := s.UpsertOAuthAccount(ctx, theauth.OAuthAccount{
		ID: ulid.New(), UserID: u1.ID, Provider: "github", ProviderUserID: "42",
		AccessTokenEnc: []byte("a1"), RefreshTokenEnc: []byte("r1"), ExpiresAt: &exp, Scope: "read",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	b, err := s.UpsertOAuthAccount(ctx, theauth.OAuthAccount{
		ID: ulid.New(), UserID: u1.ID, Provider: "github", ProviderUserID: "42",
		AccessTokenEnc: []byte("a2"), Scope: "write",
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if b.ID != a.ID || string(b.AccessTokenEnc) != "a2" || b.Scope != "write" || b.RefreshTokenEnc != nil || b.ExpiresAt != nil {
		t.Fatalf("upsert did not update in place: %+v", b)
	}

	tests := []struct {
		name string
		fn   func() error
		want error
	}{
		{"lookup hit", func() error { _, err := s.OAuthAccountByProviderUserID(ctx, "github", "42"); return err }, nil},
		{"lookup miss", func() error { _, err := s.OAuthAccountByProviderUserID(ctx, "github", "nope"); return err }, theauth.ErrStorageNotFound},
		{"move", func() error { return s.MoveOAuthAccount(ctx, "github", "42", u2.ID) }, nil},
		{"move miss", func() error { return s.MoveOAuthAccount(ctx, "github", "nope", u2.ID) }, theauth.ErrStorageNotFound},
		{"delete wrong user", func() error { return s.DeleteOAuthAccountByProvider(ctx, u1.ID, "github") }, theauth.ErrStorageNotFound},
		{"delete", func() error { return s.DeleteOAuthAccountByProvider(ctx, u2.ID, "github") }, nil},
	}
	for _, tc := range tests {
		if err := tc.fn(); !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v want %v", tc.name, err, tc.want)
		}
	}
	list, err := s.OAuthAccountsByUserID(ctx, u1.ID)
	if err != nil || list == nil || len(list) != 0 {
		t.Fatalf("empty list = %v, %v", list, err)
	}
}

func TestForeignKeysCascadeAndGuard(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)
	if err := sqlitestore.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	s, err := sqlitestore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	u := mkUser(t, s, "cascade@example.com")
	sess, err := s.CreateSession(ctx, theauth.Session{
		ID: ulid.New(), UserID: u.ID, TokenHash: []byte("th"), ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSession(ctx, theauth.Session{ID: ulid.New(), UserID: ulid.New(), TokenHash: []byte("x"), ExpiresAt: time.Now()}); err == nil {
		t.Fatal("session for unknown user was accepted")
	}
	if _, err := db.Exec(`DELETE FROM theauth_users WHERE id = ?`, u.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByID(ctx, sess.ID); !errors.Is(err, theauth.ErrStorageNotFound) {
		t.Fatalf("session survived user delete: %v", err)
	}

	off := openDB(t)
	off.SetMaxOpenConns(1)
	if _, err := off.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlitestore.New(off); err == nil {
		t.Fatal("New accepted a db with foreign keys off")
	}
	if _, err := sqlitestore.New(off, sqlitestore.AllowForeignKeysOff()); err != nil {
		t.Fatalf("AllowForeignKeysOff: %v", err)
	}
}

func TestConcurrentAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)

	t.Run("ConsumeMagicLinkOnce", func(t *testing.T) {
		hash := []byte("race-magic-link")
		if err := s.CreateMagicLink(ctx, theauth.MagicLink{
			ID: ulid.New(), Email: "m@example.com", TokenHash: hash, ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		var ok, notFound, other atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.ConsumeMagicLink(ctx, hash)
				switch {
				case err == nil:
					ok.Add(1)
				case errors.Is(err, theauth.ErrStorageNotFound):
					notFound.Add(1)
				default:
					other.Add(1)
					t.Errorf("consume: %v", err)
				}
			}()
		}
		wg.Wait()
		if ok.Load() != 1 || notFound.Load() != 15 {
			t.Fatalf("ok=%d notFound=%d other=%d", ok.Load(), notFound.Load(), other.Load())
		}
	})

	t.Run("DuplicateEmailOneWinner", func(t *testing.T) {
		var ok atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				email := "Race@example.com"
				if i%2 == 0 {
					email = "race@EXAMPLE.com"
				}
				if _, err := s.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: email}); err == nil {
					ok.Add(1)
				}
			}()
		}
		wg.Wait()
		if ok.Load() != 1 {
			t.Fatalf("%d concurrent creates of one email succeeded", ok.Load())
		}
	})

	t.Run("MixedWrites", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				u, err := s.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: fmt.Sprintf("mix%d@example.com", i)})
				if err != nil {
					t.Errorf("CreateUser: %v", err)
					return
				}
				if _, err := s.CreateSession(ctx, theauth.Session{
					ID: ulid.New(), UserID: u.ID, TokenHash: []byte(fmt.Sprintf("tok%d", i)), ExpiresAt: time.Now().Add(time.Hour),
				}); err != nil {
					t.Errorf("CreateSession: %v", err)
				}
				if err := s.SetUserPassword(ctx, u.ID, "phc"); err != nil {
					t.Errorf("SetUserPassword: %v", err)
				}
				if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{ID: ulid.New(), ActorUserID: &u.ID, Action: "mix", CreatedAt: time.Now()}}); err != nil {
					t.Errorf("InsertAuditEvents: %v", err)
				}
			}()
		}
		wg.Wait()
		evs, _, err := s.QueryAuditEvents(ctx, theauth.AuditQuery{Action: "mix", Limit: 200})
		if err != nil || len(evs) != 24 {
			t.Fatalf("audit rows = %d, %v", len(evs), err)
		}
	})
}

func TestSweepExpired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	u := mkUser(t, s, "sweep@example.com")
	now := time.Now()

	for i, exp := range []time.Duration{-time.Hour, time.Hour} {
		if _, err := s.CreateSession(ctx, theauth.Session{
			ID: ulid.New(), UserID: u.ID, TokenHash: []byte{byte(i)}, ExpiresAt: now.Add(exp),
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateMagicLink(ctx, theauth.MagicLink{
			ID: ulid.New(), Email: "sweep@example.com", TokenHash: []byte{byte(i)}, ExpiresAt: now.Add(exp),
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreatePasswordResetToken(ctx, theauth.PasswordResetToken{
			ID: ulid.New(), UserID: u.ID, TokenHash: []byte{byte(i)}, ExpiresAt: now.Add(exp),
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.SweepExpired(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := (sqlitestore.SweepResult{Sessions: 1, MagicLinks: 1, PasswordResetTokens: 1}); got != want {
		t.Fatalf("sweep = %+v want %+v", got, want)
	}
	again, _ := s.SweepExpired(ctx, now)
	if again != (sqlitestore.SweepResult{}) {
		t.Fatalf("second sweep not empty: %+v", again)
	}
}

func TestMigrate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("IdempotentAndConcurrent", func(t *testing.T) {
		db := openDB(t)
		var wg sync.WaitGroup
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := sqlitestore.Migrate(ctx, db); err != nil {
					t.Errorf("Migrate: %v", err)
				}
			}()
		}
		wg.Wait()
		if err := sqlitestore.Migrate(ctx, db); err != nil {
			t.Fatal(err)
		}
		var n, want int
		if err := db.QueryRow(`SELECT COUNT(*) FROM theauth_schema_migrations`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		migs, _ := sqlitestore.RenderMigrations()
		want = len(migs)
		if n != want {
			t.Fatalf("ledger rows = %d want %d", n, want)
		}
	})

	t.Run("PrefixCoexistsWithHostTables", func(t *testing.T) {
		db := openDB(t)
		if _, err := db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY)`); err != nil {
			t.Fatal(err)
		}
		if err := sqlitestore.Migrate(ctx, db, sqlitestore.WithTablePrefix("lr_auth_")); err != nil {
			t.Fatal(err)
		}
		var name string
		if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE name = 'lr_auth_users'`).Scan(&name); err != nil {
			t.Fatalf("prefixed table missing: %v", err)
		}
		var leaked int
		_ = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'theauth_%'`).Scan(&leaked)
		if leaked != 0 {
			t.Fatalf("%d default-prefixed objects leaked", leaked)
		}
	})

	t.Run("FoldIntoHostMigrator", func(t *testing.T) {
		db := openDB(t)
		files, err := fs.Glob(sqlitestore.Migrations(), "*.sql")
		if err != nil || len(files) < 5 {
			t.Fatalf("glob = %v, %v", files, err)
		}
		for _, f := range files {
			body, err := fs.ReadFile(sqlitestore.Migrations(), f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(string(body)); err != nil {
				t.Fatalf("apply %s: %v", f, err)
			}
		}
		s, err := sqlitestore.New(db)
		if err != nil {
			t.Fatal(err)
		}
		mkUser(t, s, "host@example.com")
	})

	t.Run("InvalidPrefixRejected", func(t *testing.T) {
		if err := sqlitestore.Migrate(ctx, openDB(t), sqlitestore.WithTablePrefix("bad-prefix;")); err == nil {
			t.Fatal("invalid prefix accepted")
		}
	})

	t.Run("FilesAreNumberedAndDashFree", func(t *testing.T) {
		migs, err := sqlitestore.RenderMigrations()
		if err != nil {
			t.Fatal(err)
		}
		for i, m := range migs {
			if want := fmt.Sprintf("%04d_", i+1); !strings.HasPrefix(m.Version, want) {
				t.Fatalf("migration %d is %q, want prefix %s", i, m.Version, want)
			}
		}
	})
}
