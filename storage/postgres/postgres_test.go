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
	mig1, err := os.ReadFile("migrations/0001_init.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	mig2, err := os.ReadFile("migrations/0002_passwords.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	mig3, err := os.ReadFile("migrations/0003_oauth_accounts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	mig4, err := os.ReadFile("migrations/0004_webauthn_credentials.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	mig5, err := os.ReadFile("migrations/0005_totp.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	mig6, err := os.ReadFile("migrations/0006_organizations.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	mig7, err := os.ReadFile("migrations/0007_saml.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	mig8, err := os.ReadFile("migrations/0008_scim.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	// Drop + recreate for clean state. Order matters: dependent tables
	// drop first (v0.5 + v0.7 reference users; v0.7 SAML/SCIM reference
	// organizations).
	_, _ = pool.Exec(context.Background(), `
		DROP TABLE IF EXISTS group_members CASCADE;
		DROP TABLE IF EXISTS groups CASCADE;
		DROP TABLE IF EXISTS scim_tokens CASCADE;
		DROP TABLE IF EXISTS saml_identities CASCADE;
		DROP TABLE IF EXISTS saml_connections CASCADE;
		DROP TABLE IF EXISTS organization_members CASCADE;
		DROP TABLE IF EXISTS organizations CASCADE;
		DROP TABLE IF EXISTS totp_recovery_codes CASCADE;
		DROP TABLE IF EXISTS totp_secrets CASCADE;
		DROP TABLE IF EXISTS webauthn_credentials CASCADE;
		DROP TABLE IF EXISTS oauth_accounts CASCADE;
		DROP TABLE IF EXISTS password_reset_tokens CASCADE;
		DROP TABLE IF EXISTS magic_links CASCADE;
		DROP TABLE IF EXISTS sessions CASCADE;
		DROP TABLE IF EXISTS users CASCADE;
	`)
	for _, m := range [][]byte{mig1, mig2, mig3, mig4, mig5, mig6, mig7, mig8} {
		if _, err := pool.Exec(context.Background(), string(m)); err != nil {
			t.Fatal(err)
		}
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

func TestPostgresPasswordRoundtrip(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	uid := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: uid, Email: "pw@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	// Before SetUserPassword: hash is empty string (NULL coalesced).
	_, ph, err := s.UserByEmailWithPassword(ctx, "pw@h.com")
	if err != nil {
		t.Fatal(err)
	}
	if ph != "" {
		t.Fatalf("expected empty password hash before SetUserPassword; got %q", ph)
	}

	if err := s.SetUserPassword(ctx, uid, "$argon2id$v=19$m=65536,t=3,p=4$AAAA$BBBB"); err != nil {
		t.Fatal(err)
	}
	got, ph, err := s.UserByEmailWithPassword(ctx, "pw@h.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != uid {
		t.Fatalf("user id mismatch")
	}
	if ph != "$argon2id$v=19$m=65536,t=3,p=4$AAAA$BBBB" {
		t.Fatalf("password hash not persisted; got %q", ph)
	}
}

func TestPostgresPasswordResetTokenConsume(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	uid := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: uid, Email: "rt@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte("reset-token"))
	rt := theauth.PasswordResetToken{
		ID: ulid.New(), UserID: uid,
		TokenHash: tokenHash[:],
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.CreatePasswordResetToken(ctx, rt); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumePasswordResetToken(ctx, tokenHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != uid {
		t.Fatal("reset token user_id mismatch")
	}
	if got.UsedAt == nil {
		t.Fatal("expected UsedAt set after consume")
	}
	if _, err := s.ConsumePasswordResetToken(ctx, tokenHash[:]); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("second consume should miss; got %v", err)
	}
}

func TestPostgresOAuthAccountUpsertAndLookup(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := New(pool)
	ctx := context.Background()

	uid := ulid.New()
	if _, err := s.CreateUser(ctx, theauth.User{ID: uid, Email: "oa@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// Insert path.
	first, err := s.UpsertOAuthAccount(ctx, theauth.OAuthAccount{
		ID:             ulid.New(),
		UserID:         uid,
		Provider:       "github",
		ProviderUserID: "42",
		AccessTokenEnc: []byte("enc-1"),
		Scope:          "read:user user:email",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	})
	if err != nil {
		t.Fatalf("insert upsert: %v", err)
	}
	if first.UserID != uid {
		t.Fatalf("UserID mismatch after insert")
	}

	// Update path: same (provider, provider_user_id) should refresh tokens
	// and bump updated_at, keep the original ID + created_at.
	second, err := s.UpsertOAuthAccount(ctx, theauth.OAuthAccount{
		ID:             ulid.New(), // ignored due to ON CONFLICT
		UserID:         uid,
		Provider:       "github",
		ProviderUserID: "42",
		AccessTokenEnc: []byte("enc-2"),
		Scope:          "read:user",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	})
	if err != nil {
		t.Fatalf("update upsert: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("ID changed across upsert; got %v want %v", second.ID, first.ID)
	}
	if string(second.AccessTokenEnc) != "enc-2" {
		t.Fatalf("access token not refreshed; got %q", second.AccessTokenEnc)
	}
	if second.Scope != "read:user" {
		t.Fatalf("scope not refreshed; got %q", second.Scope)
	}

	// Lookup hit.
	got, err := s.OAuthAccountByProviderUserID(ctx, "github", "42")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.ID != first.ID {
		t.Fatalf("lookup returned wrong row")
	}

	// Lookup miss.
	if _, err := s.OAuthAccountByProviderUserID(ctx, "github", "does-not-exist"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound; got %v", err)
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
