package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// oauthClientTestPool creates a pool against THEAUTH_TEST_PG_DSN and applies
// all 14 migrations into a fresh schema so the test is isolated and repeatable.
// The schema is dropped on cleanup.
func oauthClientTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("THEAUTH_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("THEAUTH_TEST_PG_DSN not set; skipping oauth_clients nil-slice integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	schema := "theauth_null_slices_test"
	_, _ = pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		pool.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		pool.Close()
	})

	if _, err := pool.Exec(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatalf("set search_path: %v", err)
	}

	migrations := []string{
		"migrations/0001_init.up.sql",
		"migrations/0002_passwords.up.sql",
		"migrations/0003_oauth_accounts.up.sql",
		"migrations/0004_webauthn_credentials.up.sql",
		"migrations/0005_totp.up.sql",
		"migrations/0006_organizations.up.sql",
		"migrations/0007_saml.up.sql",
		"migrations/0008_scim.up.sql",
		"migrations/0009_rbac.up.sql",
		"migrations/0010_audit.up.sql",
		"migrations/0011_oauth_clients_and_codes.up.sql",
		"migrations/0012_agents.up.sql",
		"migrations/0013_delegations.up.sql",
		"migrations/0014_jwks_keys.up.sql",
	}
	for _, path := range migrations {
		sql, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read migration %s: %v", path, err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("apply migration %s: %v", path, err)
		}
	}
	return pool
}

// TestInsertOAuthClient_NilSlices verifies that passing an OAuthClient with
// all four text[] fields set to nil does not fail with SQLSTATE 23502.
// The columns are declared NOT NULL DEFAULT '{}' in migration 0011; the bug
// was that pgx encoded a nil []string as SQL NULL, bypassing the column
// default and violating the constraint.
func TestInsertOAuthClient_NilSlices(t *testing.T) {
	pool := oauthClientTestPool(t)
	s := New(pool)
	ctx := context.Background()

	in := theauth.OAuthClient{
		ID:                  ulid.New(),
		ClientID:            "test-nil-client-" + ulid.New().String(),
		ClientName:          "nil-slice-test",
		AnonymousRegistered: true,
		// RedirectURIs, GrantTypes, ResponseTypes, Contacts are intentionally nil.
	}

	got, err := s.InsertOAuthClient(ctx, in)
	if err != nil {
		t.Fatalf("InsertOAuthClient with nil slices failed: %v", err)
	}

	// Round-trip: read the row back and verify the slice fields are non-nil
	// (pgx decodes an empty text[] from Postgres as an empty Go slice, not nil).
	retrieved, err := s.OAuthClientByClientID(ctx, got.ClientID)
	if err != nil {
		t.Fatalf("OAuthClientByClientID: %v", err)
	}

	if retrieved.RedirectURIs == nil {
		t.Error("RedirectURIs: want non-nil empty slice, got nil")
	}
	if retrieved.GrantTypes == nil {
		t.Error("GrantTypes: want non-nil empty slice, got nil")
	}
	if retrieved.ResponseTypes == nil {
		t.Error("ResponseTypes: want non-nil empty slice, got nil")
	}
	if retrieved.Contacts == nil {
		t.Error("Contacts: want non-nil empty slice, got nil")
	}
	if len(retrieved.RedirectURIs) != 0 {
		t.Errorf("RedirectURIs: want empty, got %v", retrieved.RedirectURIs)
	}
	if len(retrieved.GrantTypes) != 0 {
		t.Errorf("GrantTypes: want empty, got %v", retrieved.GrantTypes)
	}
	if len(retrieved.ResponseTypes) != 0 {
		t.Errorf("ResponseTypes: want empty, got %v", retrieved.ResponseTypes)
	}
	if len(retrieved.Contacts) != 0 {
		t.Errorf("Contacts: want empty, got %v", retrieved.Contacts)
	}
}

// TestUpdateOAuthClient_NilSlices verifies that UpdateOAuthClient also handles
// nil slices safely (same columns, same NOT NULL constraint).
func TestUpdateOAuthClient_NilSlices(t *testing.T) {
	pool := oauthClientTestPool(t)
	s := New(pool)
	ctx := context.Background()

	in := theauth.OAuthClient{
		ID:                  ulid.New(),
		ClientID:            "test-nil-update-" + ulid.New().String(),
		ClientName:          "nil-update-test",
		AnonymousRegistered: true,
		RedirectURIs:        []string{"https://example.com/cb"},
		GrantTypes:          []string{"authorization_code"},
	}

	inserted, err := s.InsertOAuthClient(ctx, in)
	if err != nil {
		t.Fatalf("InsertOAuthClient: %v", err)
	}

	// Clear all four slices to nil and update.
	inserted.RedirectURIs = nil
	inserted.GrantTypes = nil
	inserted.ResponseTypes = nil
	inserted.Contacts = nil

	if _, err := s.UpdateOAuthClient(ctx, inserted); err != nil {
		t.Fatalf("UpdateOAuthClient with nil slices failed: %v", err)
	}
}
