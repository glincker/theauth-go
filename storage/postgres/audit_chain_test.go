package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	oklog "github.com/oklog/ulid/v2"
)

func chainTestStore(t *testing.T) (*Store, func(sql string, args ...any)) {
	t.Helper()
	pool := testPool(t)
	t.Cleanup(pool.Close)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	return New(pool), exec
}

func TestAuditChainDetectsTamper(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name, sql, reason string
	}{
		{"chain metadata text", `UPDATE audit_events SET chain_metadata = '{"x":1}' WHERE id = $1`, "hash_mismatch"},
		{"jsonb column only", `UPDATE audit_events SET metadata = '{"x":1}' WHERE id = $1`, "hash_mismatch"},
		{"action", `UPDATE audit_events SET action = 'other' WHERE id = $1`, "hash_mismatch"},
		{"raw subject id", `UPDATE audit_events SET subject_id = 'user_2' WHERE id = $1`, "pseudonym_mismatch"},
		{"hash", `UPDATE audit_events SET hash = repeat('0', 64) WHERE id = $1`, "hash_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, exec := chainTestStore(t)
			var last theauth.ULID
			for i := 0; i < 3; i++ {
				last = ulid.New()
				if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
					ID: last, Action: "a", CreatedAt: time.Now(), SubjectID: "user_1",
					Metadata: map[string]any{"i": i, "z": "last", "a": []any{1, "b"}}, IP: "2001:0db8::1",
				}}); err != nil {
					t.Fatalf("insert: %v", err)
				}
			}
			res, err := s.VerifyAuditChain(ctx)
			if err != nil || !res.OK || res.Checked != 3 {
				t.Fatalf("verify = %+v, %v", res, err)
			}
			exec(tc.sql, ulidToPgUUID(last))
			res, err = s.VerifyAuditChain(ctx)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if res.OK || res.FirstBreak == nil || res.FirstBreak.Reason != tc.reason || res.FirstBreak.RowID != last.String() {
				t.Fatalf("tamper not detected: %+v (break %+v)", res, res.FirstBreak)
			}
		})
	}
}

func TestAuditChainAcceptsPreMigrationRows(t *testing.T) {
	ctx := context.Background()
	s, exec := chainTestStore(t)
	// A row as written before migration 0028: no chain position.
	exec(`INSERT INTO audit_events (id, action, metadata, created_at) VALUES ($1, 'old', '{}', now())`,
		ulidToPgUUID(ulid.New()))
	if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{ID: ulid.New(), Action: "new"}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	res, err := s.VerifyAuditChain(ctx)
	if err != nil || !res.OK || res.Checked != 1 || res.Unchained != 1 {
		t.Fatalf("verify = %+v, %v", res, err)
	}
	evs, _, err := s.QueryAuditEvents(ctx, theauth.AuditQuery{Action: "old"})
	if err != nil || len(evs) != 1 || evs[0].ChainSeq != 0 {
		t.Fatalf("legacy read: %+v, %v", evs, err)
	}
}

// TestAuditChainPerOrgAndSurvivesFKNulling checks that each organization has
// its own chain and that deleting the organization or session (which nulls the
// foreign key columns) does not break verification.
func TestAuditChainPerOrgAndSurvivesFKNulling(t *testing.T) {
	ctx := context.Background()
	s, _ := chainTestStore(t)
	mkOrg := func(slug string) theauth.ULID {
		o, err := s.InsertOrganization(ctx, theauth.Organization{ID: ulid.New(), Name: slug, Slug: slug})
		if err != nil {
			t.Fatalf("InsertOrganization: %v", err)
		}
		return o.ID
	}
	a, b := mkOrg("chain-a"), mkOrg("chain-b")
	for i := 0; i < 4; i++ {
		org := &a
		if i%2 == 1 {
			org = &b
		}
		if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{
			{ID: ulid.New(), OrganizationID: org, Action: "org.event", CreatedAt: time.Now()},
			{ID: ulid.New(), Action: "global.event", CreatedAt: time.Now()},
		}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	res, err := s.VerifyAuditChain(ctx)
	if err != nil || !res.OK || res.Checked != 8 {
		t.Fatalf("verify = %+v, %v", res, err)
	}
	if err := s.DeleteOrganization(ctx, a); err != nil {
		t.Fatalf("DeleteOrganization: %v", err)
	}
	res, err = s.VerifyAuditChain(ctx)
	if err != nil || !res.OK || res.Checked != 8 {
		t.Fatalf("after org delete = %+v, %v (break %+v)", res, err, res.FirstBreak)
	}
}

// TestAuditChainGoldenVectorMatchesSharedHash inserts the golden event pinned
// in internal/audit/chainhash_test.go (also asserted against sqlite and mysql)
// and checks the stored hash, proving the hash input is identical.
func TestAuditChainGoldenVectorMatchesSharedHash(t *testing.T) {
	ctx := context.Background()
	s, exec := chainTestStore(t)
	exec(`INSERT INTO theauth_audit_secrets (id, secret) VALUES (1, $1)`, []byte("0123456789abcdef0123456789abcdef"))
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
