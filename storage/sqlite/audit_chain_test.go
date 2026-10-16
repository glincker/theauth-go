package sqlite_test

import (
	"context"
	"testing"
	"time"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
)

func chainStore(t *testing.T) (*sqlitestore.Store, func(query string, args ...any)) {
	t.Helper()
	db := openDB(t)
	if err := sqlitestore.Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := sqlitestore.New(db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(context.Background(), query, args...); err != nil {
			t.Fatalf("exec %q: %v", query, err)
		}
	}
	return s, exec
}

func TestAuditAccountabilityFieldsPersist(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := chainStore(t)
	id := newID()
	err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
		ID: id, Action: "agent.authorize", CreatedAt: time.Now(),
		SubjectID: "user_1", ActorID: "agent_9", PolicyVersion: "v7", ApproverID: "user_2",
		DelegationChain: []string{"agent_1", "agent_9"},
		InputProvenance: map[string]any{"source": "tool_output"},
	}})
	if err != nil {
		t.Fatalf("InsertAuditEvents: %v", err)
	}
	evs, _, err := s.QueryAuditEvents(ctx, theauth.AuditQuery{Action: "agent.authorize"})
	if err != nil || len(evs) != 1 {
		t.Fatalf("query: %d, %v", len(evs), err)
	}
	e := evs[0]
	if e.SubjectID != "user_1" || e.ActorID != "agent_9" || e.PolicyVersion != "v7" || e.ApproverID != "user_2" {
		t.Fatalf("fields lost: %+v", e)
	}
	if len(e.DelegationChain) != 2 || e.DelegationChain[1] != "agent_9" || e.InputProvenance["source"] != "tool_output" {
		t.Fatalf("json fields lost: %+v", e)
	}
	if e.ChainSeq != 1 || e.Hash == "" || e.PrevHash != "" {
		t.Fatalf("chain output wrong: seq=%d hash=%q prev=%q", e.ChainSeq, e.Hash, e.PrevHash)
	}
}

func TestAuditChainVerifiesAndDetectsTamper(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, exec := chainStore(t)
	var last theauth.ULID
	for i := 0; i < 3; i++ {
		last = newID()
		if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
			ID: last, Action: "a", CreatedAt: time.Now(), SubjectID: "u", Metadata: map[string]any{"i": i},
		}}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	res, err := s.VerifyAuditChain(ctx)
	if err != nil || !res.OK || res.Checked != 3 {
		t.Fatalf("verify = %+v, %v", res, err)
	}

	exec(`UPDATE theauth_audit_events SET metadata = '{"x":1}' WHERE id = ?`, last.String())
	res, err = s.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK || res.FirstBreak == nil || res.FirstBreak.Reason != "hash_mismatch" || res.FirstBreak.RowID != last.String() {
		t.Fatalf("tamper not detected: %+v", res)
	}
}

func TestAuditChainAcceptsPreMigrationRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, exec := chainStore(t)
	// A row as written before migration 0017: no chain position.
	exec(`INSERT INTO theauth_audit_events (id, action, metadata, created_at) VALUES (?, 'old', '{}', 1)`,
		newID().String())
	if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{ID: newID(), Action: "new", CreatedAt: time.Now()}}); err != nil {
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

func TestAuditChainSupportedFlag(t *testing.T) {
	t.Parallel()
	s, _ := chainStore(t)
	if !s.ChainSupported() {
		t.Fatal("sqlite must report ChainSupported")
	}
	res, err := s.VerifyAuditChain(context.Background())
	if err != nil || !res.Supported || !res.OK {
		t.Fatalf("verify empty = %+v, %v", res, err)
	}
}
