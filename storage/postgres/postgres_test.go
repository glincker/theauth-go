package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("POSTGRES_TEST_URL")
	if url == "" {
		t.Skip("POSTGRES_TEST_URL not set; skipping Postgres integration tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	mig, err := os.ReadFile("migrations/0001_init.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	// Drop + recreate for clean state
	_, _ = pool.Exec(context.Background(), `
		DROP TABLE IF EXISTS magic_links;
		DROP TABLE IF EXISTS sessions;
		DROP TABLE IF EXISTS users;
	`)
	if _, err := pool.Exec(context.Background(), string(mig)); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestPostgresUserRoundtrip(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	u := theauth.User{ID: ulid.New(), Email: "p@q.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if _, err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := s.UserByEmail(ctx, "p@q.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "p@q.com" {
		t.Fatalf("got %q", got.Email)
	}
}

func TestPostgresSessionAndRevoke(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	uid := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: uid, Email: "s@s.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte("xyz"))
	sess := theauth.Session{
		ID: ulid.New(), UserID: uid,
		TokenHash: tokenHash[:],
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	if _, err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionByTokenHash(ctx, tokenHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil {
		t.Fatal("expected RevokedAt set")
	}
}

func TestPostgresMagicLinkConsume(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	tokenHash := sha256.Sum256([]byte("ml"))
	ml := theauth.MagicLink{
		ID: ulid.New(), Email: "m@m.com",
		TokenHash: tokenHash[:],
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	if err := s.CreateMagicLink(ctx, ml); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeMagicLink(ctx, tokenHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeMagicLink(ctx, tokenHash[:]); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("second consume should fail; got %v", err)
	}
}
