package storagetest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// AuditChainSuiteStorage is the storage RunAuditChain needs. Only backends
// that keep a tamper-evident chain (sqlite, postgres, mysql) run it. Memory
// reports ChainSupported() == false and is not run.
type AuditChainSuiteStorage interface {
	AuditSuiteStorage
	ChainSupported() bool
	VerifyAuditChain(ctx context.Context) (theauth.AuditChainResult, error)
	DeleteUserCascade(ctx context.Context, userID theauth.ULID) error
}

// RunAuditChain runs the audit hash chain contract: chained appends verify,
// concurrent writers keep the chain intact, and erasing a user blanks raw ids
// without breaking verification. Counts are compared as deltas so the suite
// can share a database with other suites.
func RunAuditChain(t *testing.T, store AuditChainSuiteStorage) {
	t.Helper()
	t.Run("AuditChain", func(t *testing.T) {
		t.Run("Supported", func(t *testing.T) { chainSupported(t, store) })
		t.Run("AppendVerifiesAndRoundTrips", func(t *testing.T) { chainAppend(t, store) })
		t.Run("ConcurrentWriters", func(t *testing.T) { chainConcurrent(t, store) })
		t.Run("SurvivesUserErasure", func(t *testing.T) { chainErasure(t, store) })
	})
}

func mustVerify(t *testing.T, store AuditChainSuiteStorage) theauth.AuditChainResult {
	t.Helper()
	res, err := store.VerifyAuditChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !res.Supported || !res.OK {
		t.Fatalf("chain does not verify: %+v (break %+v)", res, res.FirstBreak)
	}
	return res
}

func chainSupported(t *testing.T, store AuditChainSuiteStorage) {
	if !store.ChainSupported() {
		t.Fatal("ChainSupported() = false")
	}
	mustVerify(t, store)
}

func chainAppend(t *testing.T, store AuditChainSuiteStorage) {
	ctx := context.Background()
	before := mustVerify(t, store)
	id := newID()
	ev := theauth.AuditEvent{
		ID: id, Action: "storagetest.chain.append", CreatedAt: time.Now(),
		SubjectID: "user_1", ActorID: "agent_9", PolicyVersion: "v7", ApproverID: "user_2",
		DelegationChain: []string{"agent_1", "agent_9"},
		InputProvenance: map[string]any{"source": "tool_output"},
		Metadata:        map[string]any{"b": 2, "a": "x"},
		IP:              "203.0.113.7", UserAgent: "chain-test",
	}
	if err := store.InsertAuditEvents(ctx, []theauth.AuditEvent{ev}); err != nil {
		t.Fatalf("InsertAuditEvents: %v", err)
	}
	if err := store.InsertAuditEvents(ctx, []theauth.AuditEvent{
		{ID: newID(), Action: "storagetest.chain.append.2", CreatedAt: time.Now()},
		{ID: newID(), Action: "storagetest.chain.append.3"},
	}); err != nil {
		t.Fatalf("InsertAuditEvents batch: %v", err)
	}
	after := mustVerify(t, store)
	if after.Checked != before.Checked+3 {
		t.Fatalf("checked = %d, want %d", after.Checked, before.Checked+3)
	}
	got, _, err := store.QueryAuditEvents(ctx, theauth.AuditQuery{Action: "storagetest.chain.append"})
	if err != nil || len(got) != 1 {
		t.Fatalf("query: %d events, %v", len(got), err)
	}
	e := got[0]
	if e.SubjectID != "user_1" || e.ActorID != "agent_9" || e.PolicyVersion != "v7" || e.ApproverID != "user_2" {
		t.Fatalf("accountability fields lost: %+v", e)
	}
	if len(e.DelegationChain) != 2 || e.DelegationChain[1] != "agent_9" || e.InputProvenance["source"] != "tool_output" {
		t.Fatalf("json fields lost: %+v", e)
	}
	if e.ChainSeq == 0 || e.Hash == "" {
		t.Fatalf("chain output missing: seq=%d hash=%q", e.ChainSeq, e.Hash)
	}
	if _, ok := e.Metadata["_accountability"]; ok {
		t.Fatalf("accountability must be native columns, not metadata: %+v", e.Metadata)
	}
}

func chainConcurrent(t *testing.T, store AuditChainSuiteStorage) {
	ctx := context.Background()
	before := mustVerify(t, store)
	const writers, batches, perBatch = 8, 5, 3
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for b := 0; b < batches; b++ {
				batch := make([]theauth.AuditEvent, perBatch)
				for i := range batch {
					batch[i] = theauth.AuditEvent{
						ID: newID(), Action: "storagetest.chain.concurrent", CreatedAt: time.Now(),
						SubjectID: fmt.Sprintf("u%d", w), Metadata: map[string]any{"w": w, "b": b, "i": i},
					}
				}
				if err := store.InsertAuditEvents(ctx, batch); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent InsertAuditEvents: %v", err)
	}
	after := mustVerify(t, store)
	if want := before.Checked + writers*batches*perBatch; after.Checked != want {
		t.Fatalf("checked = %d, want %d", after.Checked, want)
	}
}

func chainErasure(t *testing.T, store AuditChainSuiteStorage) {
	ctx := context.Background()
	u, err := store.CreateUser(ctx, theauth.User{
		ID: newID(), Email: "chain-erase@storagetest.example", CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := u.ID
	for i := 0; i < 3; i++ {
		actor := uid
		if err := store.InsertAuditEvents(ctx, []theauth.AuditEvent{{
			ID: newID(), Action: "storagetest.chain.erase", CreatedAt: time.Now(), ActorUserID: &actor,
			SubjectID: uid.String(), ActorID: "agent_1", ApproverID: uid.String(),
			Metadata: map[string]any{"i": i},
		}}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	before := mustVerify(t, store)
	if err := store.DeleteUserCascade(ctx, uid); err != nil {
		t.Fatalf("DeleteUserCascade: %v", err)
	}
	after := mustVerify(t, store)
	if after.Checked != before.Checked || after.Erased != before.Erased+3 {
		t.Fatalf("after erasure = %+v, before = %+v", after, before)
	}
	got, _, err := store.QueryAuditEvents(ctx, theauth.AuditQuery{Action: "storagetest.chain.erase"})
	if err != nil || len(got) != 3 {
		t.Fatalf("query: %d events, %v", len(got), err)
	}
	for _, e := range got {
		if e.ActorUserID != nil || e.SubjectID != "" || e.ApproverID != "" {
			t.Fatalf("raw ids survived erasure: %+v", e)
		}
		if e.ActorID != "agent_1" || e.Hash == "" {
			t.Fatalf("non-personal fields changed: %+v", e)
		}
	}
}
