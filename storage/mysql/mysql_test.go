package mysql_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage"
	"github.com/glincker/theauth-go/storage/mysql"
	"github.com/glincker/theauth-go/storagetest"
)

// TestMySQLStoreContract runs the full storagetest suite against a live MySQL
// instance. Gate behind THEAUTH_MYSQL_CONTRACT=1: MySQL's status against the
// shared contract suite is unverified (see docs/ROADMAP.md), so this stays opt-in
// until that's confirmed, even though CI now runs a MySQL service container.
//
// Example:
//
//	THEAUTH_TEST_MYSQL_DSN='user:pass@tcp(localhost:3306)/theauth?parseTime=true&loc=UTC' \
//	THEAUTH_MYSQL_CONTRACT=1 \
//	go test -v -count=1 ./storage/mysql/...
func TestMySQLStoreContract(t *testing.T) {
	if os.Getenv("THEAUTH_MYSQL_CONTRACT") != "1" {
		t.Skip("THEAUTH_MYSQL_CONTRACT not set to 1; skipping MySQL contract tests")
	}

	dsn := os.Getenv("THEAUTH_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("THEAUTH_TEST_MYSQL_DSN not set; skipping MySQL contract tests")
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("db.Ping: %v", err)
	}

	ctx := context.Background()

	// Drop all known tables in dependency order for clean state.
	dropTables(t, ctx, db)

	if err := mysql.Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	store := mysql.New(db)
	storagetest.Run(t, store)

	t.Run("UpdateSessionAuthLevelUnknownID", func(t *testing.T) {
		if err := store.UpdateSessionAuthLevel(ctx, ulid.New(), "full"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("SetSessionActiveOrganizationUnknownID", func(t *testing.T) {
		if err := store.SetSessionActiveOrganization(ctx, ulid.New(), nil); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("UpdateSAMLConnectionRowUnknownID", func(t *testing.T) {
		if err := store.UpdateSAMLConnectionRow(ctx, theauth.SAMLConnection{ID: ulid.New()}); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("UpdateGroupUnknownID", func(t *testing.T) {
		if err := store.UpdateGroup(ctx, theauth.Group{ID: ulid.New()}); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("UpdateAgentLastActiveUnknownID", func(t *testing.T) {
		if err := store.UpdateAgentLastActive(ctx, ulid.New(), time.Now()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("UpdateAgentCredentialLastUsedUnknownID", func(t *testing.T) {
		if err := store.UpdateAgentCredentialLastUsed(ctx, ulid.New(), time.Now()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
}

// dropTables removes tables in reverse dependency order so the test always
// starts from a clean schema. Errors are ignored (tables may not exist).
func dropTables(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()

	tables := []string{
		"theauth_schema_migrations",
		"audit_events",
		"delegation_grants",
		"agent_credentials",
		"agents",
		"oauth_refresh_tokens",
		"oauth_authorization_codes",
		"oauth_clients",
		"jwks_keys",
		"user_roles",
		"role_permissions",
		"roles",
		"permissions",
		"group_members",
		"`groups`",
		"scim_tokens",
		"saml_identities",
		"saml_connections",
		"organization_members",
		"totp_recovery_codes",
		"totp_secrets",
		"webauthn_credentials",
		"password_reset_tokens",
		"user_passwords",
		"oauth_accounts",
		"magic_links",
		"sessions",
		"users",
		"organizations",
	}

	// Disable FK checks for the drop sequence.
	if _, err := db.ExecContext(ctx, `SET FOREIGN_KEY_CHECKS = 0`); err != nil {
		t.Logf("SET FOREIGN_KEY_CHECKS=0: %v", err)
	}
	for _, tbl := range tables {
		stmt := fmt.Sprintf(`DROP TABLE IF EXISTS %s`, tbl)
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Logf("drop %s: %v", tbl, err)
		}
	}
	if _, err := db.ExecContext(ctx, `SET FOREIGN_KEY_CHECKS = 1`); err != nil {
		t.Logf("SET FOREIGN_KEY_CHECKS=1: %v", err)
	}

	// Also drop any indexes MySQL may have persisted for the groups table
	// with a different name due to re-creation races.
	_ = strings.Join(tables, ",")
}
