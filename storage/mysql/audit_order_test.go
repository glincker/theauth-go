package mysql

import (
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/storagetest"
)

var _ storagetest.AuditOrderCapable = (*Store)(nil)

func writeOrderMigration(t *testing.T) string {
	t.Helper()
	files, err := loadMigrationFiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.version, "0031_audit_write_order") {
			return f.body
		}
	}
	t.Fatal("migration 0031_audit_write_order not embedded")
	return ""
}

// TestAuditWriteOrderMigrationSplits needs no database: it checks the statement shapes the
// migrator runs and that no dash characters sneak into the SQL.
func TestAuditWriteOrderMigrationSplits(t *testing.T) {
	body := writeOrderMigration(t)
	if strings.ContainsAny(body, "\u2013\u2014") {
		t.Fatal("migration contains an en or em dash")
	}
	stmts := splitStatements(body)
	wantPrefixes := []string{
		"ALTER TABLE audit_events\n    ADD COLUMN recorded_at_us BIGINT NULL",
		"UPDATE audit_events\n   SET recorded_at_us = TIMESTAMPDIFF(MICROSECOND",
		"UPDATE audit_events SET event = CASE action",
		"ALTER TABLE audit_events\n    ALTER COLUMN recorded_at_us SET DEFAULT",
		"ALTER TABLE theauth_audit_chain_heads ADD COLUMN recorded_at_us BIGINT NOT NULL DEFAULT 0",
		"UPDATE theauth_audit_chain_heads h",
		"CREATE INDEX idx_audit_recorded ON audit_events (recorded_at_us, id)",
		"CREATE INDEX idx_audit_org_recorded ON audit_events (organization_id, recorded_at_us, id)",
		"CREATE INDEX idx_audit_event_recorded ON audit_events (event, recorded_at_us, id)",
	}
	if len(stmts) != len(wantPrefixes) {
		t.Fatalf("want %d statements, got %d: %#v", len(wantPrefixes), len(stmts), stmts)
	}
	for i, p := range wantPrefixes {
		if !strings.HasPrefix(stmts[i], p) {
			t.Fatalf("statement %d = %q, want prefix %q", i, stmts[i], p)
		}
	}
}

// TestAuditWriteOrderBackfillMatchesVocabulary keeps the SQL CASE in step with
// audit.ActionEvents, in both directions.
func TestAuditWriteOrderBackfillMatchesVocabulary(t *testing.T) {
	stmts := splitStatements(writeOrderMigration(t))
	caseStmt := stmts[2]
	want := audit.ActionEvents()
	for action, event := range want {
		if !strings.Contains(caseStmt, "WHEN '"+action+"'") || !strings.Contains(caseStmt, "THEN '"+event+"'") {
			t.Errorf("backfill CASE lacks %s -> %s", action, event)
		}
		if !strings.Contains(caseStmt, "'"+action+"',") && !strings.Contains(caseStmt, "'"+action+"')") {
			t.Errorf("backfill IN list lacks %s", action)
		}
	}
	if got := strings.Count(caseStmt, "WHEN '"); got != len(want) {
		t.Errorf("backfill CASE has %d WHEN arms, vocabulary has %d", got, len(want))
	}
	for _, unmapped := range []string{"agent.suspended", "approval.decided", "policy.denied"} {
		if strings.Contains(caseStmt, unmapped) {
			t.Errorf("backfill must leave %s NULL", unmapped)
		}
	}
}
