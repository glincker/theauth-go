package mysql_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/mysql"
	oklog "github.com/oklog/ulid/v2"
)

func newChainID() theauth.ULID { return ulid.New() }

func chainTestStore(t *testing.T) (*mysql.Store, *sql.DB) {
	t.Helper()
	if os.Getenv("THEAUTH_MYSQL_CONTRACT") != "1" || os.Getenv("THEAUTH_TEST_MYSQL_DSN") == "" {
		t.Skip("THEAUTH_MYSQL_CONTRACT=1 and THEAUTH_TEST_MYSQL_DSN required; skipping MySQL audit chain tests")
	}
	db, err := sql.Open("mysql", os.Getenv("THEAUTH_TEST_MYSQL_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	dropTables(t, ctx, db)
	if err := mysql.Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return mysql.New(db), db
}

// TestAuditChainGoldenVectorMatchesSharedHash checks the stored hash of the golden event pinned in
// internal/audit (also asserted for sqlite and postgres). Needs a live MySQL.
func TestAuditChainGoldenVectorMatchesSharedHash(t *testing.T) {
	ctx := context.Background()
	s, db := chainTestStore(t)
	if _, err := db.ExecContext(ctx, `INSERT INTO theauth_audit_secrets (id, secret) VALUES (1, ?)`,
		[]byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	id, err := oklog.Parse("01JAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
		ID: theauth.ULID(id), Action: "agent.authorize", TargetType: "tool", TargetID: "t1",
		Metadata: map[string]any{"b": 2, "a": "x"}, IP: "203.0.113.7", UserAgent: "golden",
		CreatedAt: time.UnixMicro(1760000000123456), SubjectID: "user_1", ActorID: "agent_9",
		PolicyVersion: "v7", ApproverID: "user_2", DelegationChain: []string{"agent_1", "agent_9"},
		InputProvenance: map[string]any{"source": "tool_output"},
	}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	evs, _, err := s.QueryAuditEvents(ctx, theauth.AuditQuery{Action: "agent.authorize"})
	const want = "725905a7b0acf9e2066f9dfda03a95db25fa4797aceab17401144b6427ae14fe"
	if err != nil || len(evs) != 1 || evs[0].Hash != want {
		t.Fatalf("golden hash mismatch: %+v, %v", evs, err)
	}
	if res, err := s.VerifyAuditChain(ctx); err != nil || !res.OK || res.Checked != 1 {
		t.Fatalf("verify = %+v, %v", res, err)
	}
}

func TestAuditChainDetectsTamper(t *testing.T) {
	ctx := context.Background()
	cases := []struct{ name, sql, reason string }{
		{"chain metadata text", "UPDATE audit_events SET chain_metadata = '{\"x\":1}' WHERE action = 'a' AND chain_seq = 3", "hash_mismatch"},
		{"json column only", "UPDATE audit_events SET metadata = '{\"x\":1}' WHERE action = 'a' AND chain_seq = 3", "hash_mismatch"},
		{"action", "UPDATE audit_events SET action = 'other' WHERE action = 'a' AND chain_seq = 3", "hash_mismatch"},
		{"raw subject id", "UPDATE audit_events SET subject_id = 'user_2' WHERE action = 'a' AND chain_seq = 3", "pseudonym_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, db := chainTestStore(t)
			for i := 0; i < 3; i++ {
				if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
					ID: newChainID(), Action: "a", CreatedAt: time.Now(), SubjectID: "user_1",
					Metadata: map[string]any{"i": i, "z": "last", "a": []any{1, "b"}}, IP: "2001:db8::1",
				}}); err != nil {
					t.Fatalf("insert: %v", err)
				}
			}
			if res, err := s.VerifyAuditChain(ctx); err != nil || !res.OK || res.Checked != 3 {
				t.Fatalf("verify = %+v, %v", res, err)
			}
			if _, err := db.ExecContext(ctx, tc.sql); err != nil {
				t.Fatal(err)
			}
			res, err := s.VerifyAuditChain(ctx)
			if err != nil || res.OK || res.FirstBreak == nil || res.FirstBreak.Reason != tc.reason {
				t.Fatalf("tamper not detected: %+v, %v", res, err)
			}
		})
	}
}

func TestAuditChainAcceptsPreMigrationRows(t *testing.T) {
	ctx := context.Background()
	s, db := chainTestStore(t)
	if _, err := db.ExecContext(ctx, `INSERT INTO audit_events (id, action, metadata, created_at) VALUES (?, 'old', '{}', NOW(6))`,
		func() []byte { id := newChainID(); return id[:] }()); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{ID: newChainID(), Action: "new"}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	res, err := s.VerifyAuditChain(ctx)
	if err != nil || !res.OK || res.Checked != 1 || res.Unchained != 1 {
		t.Fatalf("verify = %+v, %v", res, err)
	}
}

// TestAuditChainIgnoresWriteOrderColumns covers rows written before migration 0031 (event and
// recorded_at_us NULL, as the migration leaves unmapped rows) and rows with arbitrary values:
// neither column is hashed, so the chain verifies in all three states. Needs a live MySQL.
func TestAuditChainIgnoresWriteOrderColumns(t *testing.T) {
	ctx := context.Background()
	s, db := chainTestStore(t)
	org := newChainID()
	if _, err := db.ExecContext(ctx, `INSERT INTO organizations (id, name, slug) VALUES (?, 'o', ?)`, org[:], "o-"+org.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	var evs []theauth.AuditEvent
	for i := 0; i < 3; i++ {
		o := org
		evs = append(evs, theauth.AuditEvent{ID: newChainID(), OrganizationID: &o, Action: "agent.authorize",
			Event: "authorize", CreatedAt: time.UnixMicro(1760000000000000 + int64(i)*1000)})
	}
	if err := s.InsertAuditEvents(ctx, evs); err != nil {
		t.Fatalf("insert: %v", err)
	}
	verify := func(stage string) {
		t.Helper()
		res, err := s.VerifyAuditChain(ctx)
		if err != nil || !res.OK || res.Checked != 3 {
			t.Fatalf("%s: verify = %+v, %v", stage, res, err)
		}
	}
	verify("written with columns")
	if _, err := db.ExecContext(ctx, `UPDATE audit_events SET event = NULL, recorded_at_us = NULL`); err != nil {
		t.Fatal(err)
	}
	verify("pre-migration shape (NULL columns)")
	if _, err := db.ExecContext(ctx, `UPDATE audit_events SET event = 'other', recorded_at_us = 7`); err != nil {
		t.Fatal(err)
	}
	verify("rewritten columns")
}

// TestAuditWriteOrderBackfillUTC applies the 0031 backfill expression to a known created_at
// under a non-UTC session time zone and expects the UTC epoch microseconds. Needs a live MySQL.
func TestAuditWriteOrderBackfillUTC(t *testing.T) {
	ctx := context.Background()
	_, db := chainTestStore(t)
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SET time_zone = '+05:30'`); err != nil {
		t.Fatal(err)
	}
	var got int64
	if err := conn.QueryRowContext(ctx, `SELECT TIMESTAMPDIFF(MICROSECOND, '1970-01-01 00:00:00', '2025-10-09 08:53:20.123456')`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if want := int64(1760000000123456); got != want {
		t.Fatalf("backfill expression = %d, want %d", got, want)
	}
}
