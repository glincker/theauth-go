package mysql

import (
	"strings"
	"testing"
)

// TestAuditAccountabilityMigrationSplits needs no database: it checks that embedded 0027 splits
// into the four statements the migrator runs.
func TestAuditAccountabilityMigrationSplits(t *testing.T) {
	files, err := loadMigrationFiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !strings.HasPrefix(f.version, "0027_audit_accountability") {
			continue
		}
		stmts := splitStatements(f.body)
		if len(stmts) != 4 {
			t.Fatalf("want 4 statements, got %d: %#v", len(stmts), stmts)
		}
		for i, prefix := range []string{"ALTER TABLE audit_events", "CREATE UNIQUE INDEX",
			"CREATE TABLE IF NOT EXISTS theauth_audit_chain_heads", "CREATE TABLE IF NOT EXISTS theauth_audit_secrets"} {
			if !strings.HasPrefix(stmts[i], prefix) {
				t.Fatalf("statement %d = %q, want prefix %q", i, stmts[i], prefix)
			}
		}
		return
	}
	t.Fatal("migration 0027_audit_accountability not embedded")
}
