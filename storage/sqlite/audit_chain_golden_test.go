package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/oklog/ulid/v2"
)

// The event, secret and hash below are the golden vector pinned in
// internal/audit/chainhash_test.go and mirrored in the postgres and mysql
// tests. storage/sqlite cannot import internal/audit, so this is what keeps
// its copy of the hash definition identical to the shared one.
const (
	goldenSecret = "0123456789abcdef0123456789abcdef"
	goldenHash   = "725905a7b0acf9e2066f9dfda03a95db25fa4797aceab17401144b6427ae14fe"
)

func TestAuditChainGoldenVectorMatchesSharedHash(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, exec := chainStore(t)
	exec(`INSERT INTO theauth_audit_secrets (id, secret, created_at) VALUES (1, ?, 1)`, []byte(goldenSecret))
	id, err := ulid.Parse("01JAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
		ID: id, Action: "agent.authorize", TargetType: "tool", TargetID: "t1",
		Metadata: map[string]any{"b": 2, "a": "x"}, IP: "203.0.113.7", UserAgent: "golden",
		CreatedAt: time.UnixMicro(1760000000123456), SubjectID: "user_1", ActorID: "agent_9",
		PolicyVersion: "v7", ApproverID: "user_2", DelegationChain: []string{"agent_1", "agent_9"},
		InputProvenance: map[string]any{"source": "tool_output"},
	}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	evs, _, err := s.QueryAuditEvents(ctx, theauth.AuditQuery{Action: "agent.authorize"})
	if err != nil || len(evs) != 1 {
		t.Fatalf("query: %d, %v", len(evs), err)
	}
	if evs[0].Hash != goldenHash {
		t.Fatalf("sqlite hash = %s, want %s", evs[0].Hash, goldenHash)
	}
}
