package mysql

import (
	"context"
	"database/sql"
	"os"
	"testing"
)

// resetSchema drops every table in the current schema so a test can rebuild a database from
// migration zero. It pins one connection because FOREIGN_KEY_CHECKS is a session variable.
func resetSchema(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SET FOREIGN_KEY_CHECKS = 0`); err != nil {
		t.Fatal(err)
	}
	rows, err := conn.QueryContext(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	_ = rows.Close()
	for _, n := range names {
		if _, err := conn.ExecContext(ctx, "DROP TABLE IF EXISTS `"+n+"`"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.ExecContext(ctx, `SET FOREIGN_KEY_CHECKS = 1`); err != nil {
		t.Fatal(err)
	}
}

func mustExec(t *testing.T, ctx context.Context, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(ctx, q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// TestMigration0034UpgradesOverExistingData builds the schema as it stood at migration 0033, fills
// it with the rows the old schema allowed (duplicate system role names, including ones that differ
// only by case, each with members and permissions) and then applies 0034. The functional unique
// index in 0034 fails on such rows unless the migration merges them first.
func TestMigration0034UpgradesOverExistingData(t *testing.T) {
	dsn := os.Getenv("THEAUTH_TEST_MYSQL_DSN")
	if os.Getenv("THEAUTH_MYSQL_CONTRACT") != "1" || dsn == "" {
		t.Skip("THEAUTH_MYSQL_CONTRACT=1 and THEAUTH_TEST_MYSQL_DSN required; skipping MySQL upgrade test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	resetSchema(t, ctx, db)
	if err := migrateBefore(ctx, db, "0034"); err != nil {
		t.Fatalf("migrate to 0033: %v", err)
	}

	id := func(n byte) []byte { return append(make([]byte, 15), n) }
	u1, u2, u3 := id(1), id(2), id(3)
	for i, u := range [][]byte{u1, u2, u3} {
		mustExec(t, ctx, db, `INSERT INTO users (id, email) VALUES (?, ?)`, u, string(rune('a'+i))+"@upgrade.example")
	}
	// Three system roles that the old schema let in: same name, and one that differs by case only.
	r1, r2, r3, orgRole := id(11), id(12), id(13), id(14)
	mustExec(t, ctx, db, `INSERT INTO roles (id, organization_id, name) VALUES (?, NULL, 'admin'), (?, NULL, 'admin'), (?, NULL, 'Admin')`, r1, r2, r3)
	p1, p2 := id(21), id(22)
	mustExec(t, ctx, db, `INSERT INTO permissions (id, name) VALUES (?, 'p.one'), (?, 'p.two')`, p1, p2)
	mustExec(t, ctx, db, `INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?), (?, ?), (?, ?)`, r1, p1, r2, p1, r3, p2)
	// u1 holds two of the duplicates (a merge must not violate user_roles primary key), u2 and u3 one each.
	mustExec(t, ctx, db, `INSERT INTO user_roles (user_id, role_id) VALUES (?, ?), (?, ?), (?, ?), (?, ?)`, u1, r1, u1, r2, u2, r2, u3, r3)
	_ = orgRole

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("applying 0034 over existing data failed: %v", err)
	}

	var roles int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM roles WHERE organization_id IS NULL AND name = 'admin'`).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if roles != 1 {
		t.Fatalf("system roles named admin after upgrade = %d, want 1", roles)
	}
	var members int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_roles`).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if members != 3 {
		t.Fatalf("user_roles after merge = %d, want 3 (u1, u2, u3 each keep the role)", members)
	}
	var perms int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM role_permissions`).Scan(&perms); err != nil {
		t.Fatal(err)
	}
	if perms != 2 {
		t.Fatalf("role_permissions after merge = %d, want 2 (p.one and p.two on the survivor)", perms)
	}
	// The index now rejects a new duplicate.
	if _, err := db.ExecContext(ctx, `INSERT INTO roles (id, organization_id, name) VALUES (?, NULL, 'ADMIN')`, id(15)); err == nil {
		t.Fatal("duplicate system role accepted after 0034")
	}
}

// TestMigration0034SamlNameIDCaseSensitive checks the collation half of 0034 over existing rows.
func TestMigration0034SamlNameIDCaseSensitive(t *testing.T) {
	dsn := os.Getenv("THEAUTH_TEST_MYSQL_DSN")
	if os.Getenv("THEAUTH_MYSQL_CONTRACT") != "1" || dsn == "" {
		t.Skip("THEAUTH_MYSQL_CONTRACT=1 and THEAUTH_TEST_MYSQL_DSN required; skipping MySQL upgrade test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	resetSchema(t, ctx, db)
	if err := migrateBefore(ctx, db, "0034"); err != nil {
		t.Fatalf("migrate to 0033: %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("applying 0034: %v", err)
	}
	var coll string
	err = db.QueryRowContext(ctx, `SELECT collation_name FROM information_schema.columns
		WHERE table_schema = DATABASE() AND table_name = 'saml_identities' AND column_name = 'name_id'`).Scan(&coll)
	if err != nil || coll != "utf8mb4_bin" {
		t.Fatalf("name_id collation = %q (%v), want utf8mb4_bin", coll, err)
	}
}
