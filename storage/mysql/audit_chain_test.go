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

// TestAuditChainGoldenVectorMatchesSharedHash inserts the golden event pinned
// in internal/audit/chainhash_test.go (also asserted against sqlite and
// postgres) and checks the stored hash. Needs a live MySQL (see capsStore).
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
