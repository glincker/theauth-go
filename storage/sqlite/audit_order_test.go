package sqlite_test

import (
	"context"
	"testing"
	"time"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storagetest"
)

func TestSQLiteAuditOrderContract(t *testing.T) {
	t.Parallel()
	storagetest.RunAuditOrder(t, newStore(t))
}

func TestSQLiteAuditOrderDeclared(t *testing.T) {
	t.Parallel()
	var s storagetest.AuditOrderCapable = &sqlitestore.Store{}
	if !s.AuditOrderSupported() {
		t.Fatal("sqlite must declare AuditOrderSupported")
	}
}

func verifyOK(t *testing.T, s *sqlitestore.Store, when string) {
	t.Helper()
	res, err := s.VerifyAuditChain(context.Background())
	if err != nil || !res.OK {
		t.Fatalf("chain must verify %s: ok=%v err=%v res=%+v", when, res.OK, err, res)
	}
}

// TestAuditWriteOrderMigrationKeepsOldChain writes a chain, rolls the schema back to its state
// before migration 0036, writes with the old shape, migrates again and checks the chain still
// verifies, the backfill is right and new writes stamp above the backfilled head.
func TestAuditWriteOrderMigrationKeepsOldChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)
	if err := sqlitestore.Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := sqlitestore.New(db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	exec := func(query string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Fatalf("exec %q: %v", query, err)
		}
	}
	base := time.UnixMicro(1760000000123456)
	for i, action := range []string{"agent.authorize", "custom.action", "agent.revoked"} {
		if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
			ID: newID(), Action: action, CreatedAt: base.Add(time.Duration(i) * time.Second),
			SubjectID: "user_1", Metadata: map[string]any{"i": i},
		}}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	for _, stmt := range []string{
		`DROP TRIGGER theauth_audit_recorded_default`,
		`DROP INDEX theauth_audit_recorded_idx`,
		`DROP INDEX theauth_audit_org_recorded_idx`,
		`DROP INDEX theauth_audit_event_recorded_idx`,
		`ALTER TABLE theauth_audit_events DROP COLUMN recorded_at_us`,
		`ALTER TABLE theauth_audit_events DROP COLUMN event`,
		`DELETE FROM theauth_schema_migrations WHERE version = '0036_audit_write_order'`,
	} {
		exec(stmt)
	}
	verifyOK(t, s, "in the pre-0036 schema")

	// A writer on the old schema still chains and reads back, ordered by created_at.
	if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
		ID: newID(), Action: "old.writer", CreatedAt: base.Add(10 * time.Second),
	}}); err != nil {
		t.Fatalf("pre-0036 insert: %v", err)
	}
	old, _, err := s.QueryAuditEvents(ctx, theauth.AuditQuery{Order: theauth.AuditOrderAsc})
	if err != nil || len(old) != 4 || old[3].Action != "old.writer" || old[3].ChainSeq != 4 {
		t.Fatalf("pre-0036 read: %d rows, %v", len(old), err)
	}
	verifyOK(t, s, "with a pre-0036 row")

	if err := sqlitestore.Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	verifyOK(t, s, "after 0036")
	evs, _, err := s.QueryAuditEvents(ctx, theauth.AuditQuery{Order: theauth.AuditOrderAsc})
	if err != nil || len(evs) != 4 {
		t.Fatalf("read after migrate: %d rows, %v", len(evs), err)
	}
	wantEvent := []string{"authorize", "", "agent.revoke", ""}
	for i, e := range evs {
		if want := e.CreatedAt.UnixMicro(); e.RecordedAtUs != want {
			t.Fatalf("row %d recorded_at_us = %d, want %d", i, e.RecordedAtUs, want)
		}
		if e.Event != wantEvent[i] {
			t.Fatalf("row %d event = %q, want %q", i, e.Event, wantEvent[i])
		}
	}
	// A write after the migration stamps above the chain head even though its created_at is older
	// and the caller supplies a bogus stamp.
	if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
		ID: newID(), Action: "after", CreatedAt: base.Add(-time.Hour), RecordedAtUs: 1, Event: "authorize",
	}}); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.QueryAuditEvents(ctx, theauth.AuditQuery{Limit: 1})
	if err != nil || len(got) != 1 || got[0].Action != "after" || got[0].RecordedAtUs <= evs[3].RecordedAtUs || got[0].Event != "authorize" {
		t.Fatalf("post-migration write must sort last: %+v, %v", got, err)
	}
	verifyOK(t, s, "with a post-migration row")
}

// TestAuditRecordedDefaultTrigger covers a row inserted by a binary that predates 0036: the
// trigger stamps it from created_at so keyset paging never skips it.
func TestAuditRecordedDefaultTrigger(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, exec := chainStore(t)
	exec(`INSERT INTO theauth_audit_events (id, action, created_at) VALUES ('01HZZZZZZZZZZZZZZZZZZZZZZZ', 'old.binary', 1760000000000000)`)
	evs, _, err := s.QueryAuditEvents(ctx, theauth.AuditQuery{Action: "old.binary"})
	if err != nil || len(evs) != 1 || evs[0].RecordedAtUs != 1760000000000000 {
		t.Fatalf("trigger stamp: %+v, %v", evs, err)
	}
}
