package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storagetest"
)

// TestPostgresAuditOrderContract runs the write order contract. The older AuditEvents contract
// inserts a random actor user id that violates audit_events_actor_user_id_fkey on Postgres (a
// known gap of the opt-in TestPostgresStoreContract), so only RunAuditOrder runs here.
func TestPostgresAuditOrderContract(t *testing.T) {
	storagetest.RunAuditOrder(t, capsStore(t))
}

func TestPostgresAuditOrderDeclared(t *testing.T) {
	var s storagetest.AuditOrderCapable = &Store{}
	if !s.AuditOrderSupported() {
		t.Fatal("postgres must declare AuditOrderSupported")
	}
}

// TestAuditWriteOrderMigrationKeepsOldChain writes a chain, rolls the schema back to its state
// before migration 0032, migrates again and checks the chain still verifies, the backfill is
// right and new writes stamp above the backfilled head.
func TestAuditWriteOrderMigrationKeepsOldChain(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	t.Cleanup(pool.Close)
	s := New(pool)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	base := time.UnixMicro(1760000000123456)
	for i, action := range []string{"agent.authorize", "custom.action", "agent.revoked"} {
		if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
			ID: ulid.New(), Action: action, CreatedAt: base.Add(time.Duration(i) * time.Second),
			SubjectID: "user_1", Metadata: map[string]any{"i": i},
		}}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	hashes := func() map[string]string {
		rows, err := pool.Query(ctx, `SELECT action, hash FROM audit_events`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var a, h string
			if err := rows.Scan(&a, &h); err != nil {
				t.Fatal(err)
			}
			out[a] = h
		}
		return out
	}
	before := hashes()

	down, err := os.ReadFile("migrations/0032_audit_write_order.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(string(down))
	exec(`DELETE FROM theauth_schema_migrations WHERE version = '0032_audit_write_order'`)
	if res, err := verifyViaFreshQuery(ctx, s); err != nil || !res {
		t.Fatalf("chain must verify in the pre-0032 schema: ok=%v err=%v", res, err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res, err := verifyViaFreshQuery(ctx, s); err != nil || !res {
		t.Fatalf("chain must verify after 0032: ok=%v err=%v", res, err)
	}
	for a, h := range hashes() {
		if before[a] != h {
			t.Fatalf("hash of %q changed across migration", a)
		}
	}
	evs, _, err := s.QueryAuditEvents(ctx, theauth.AuditQuery{Order: theauth.AuditOrderAsc})
	if err != nil || len(evs) != 3 {
		t.Fatalf("read after migrate: %d rows, %v", len(evs), err)
	}
	wantEvent := []string{"authorize", "", "agent.revoke"}
	for i, e := range evs {
		if want := base.Add(time.Duration(i) * time.Second).UnixMicro(); e.RecordedAtUs != want {
			t.Fatalf("row %d recorded_at_us = %d, want %d", i, e.RecordedAtUs, want)
		}
		if e.Event != wantEvent[i] {
			t.Fatalf("row %d event = %q, want %q", i, e.Event, wantEvent[i])
		}
	}
	// A write after the migration stamps above the backfilled chain head, even though its
	// created_at is older and the caller supplies a bogus stamp.
	if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
		ID: ulid.New(), Action: "after", CreatedAt: base.Add(-time.Hour), RecordedAtUs: 1,
	}}); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.QueryAuditEvents(ctx, theauth.AuditQuery{Limit: 1})
	if err != nil || len(got) != 1 || got[0].Action != "after" || got[0].RecordedAtUs <= evs[2].RecordedAtUs {
		t.Fatalf("post-migration write must sort last: %+v, %v", got, err)
	}
	if ok, err := verifyViaFreshQuery(ctx, s); err != nil || !ok {
		t.Fatalf("chain must verify with a post-migration row: ok=%v err=%v", ok, err)
	}
}

func verifyViaFreshQuery(ctx context.Context, s *Store) (bool, error) {
	res, err := s.VerifyAuditChain(ctx)
	return res.OK, err
}
