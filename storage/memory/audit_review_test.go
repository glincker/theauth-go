package memory

import (
	"context"
	"sync"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/audit/checkpoint"
)

// A caller that edits an event returned by QueryAuditEvents must not change what the chain hashed.
func TestMemoryAuditChainSurvivesMutatedQueryResults(t *testing.T) {
	ctx := context.Background()
	s := New()
	ev := chainEvent("a")
	ev.InputProvenance = map[string]any{"k": "v"}
	ev.DelegationChain = []string{"x"}
	if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{ev}); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.QueryAuditEvents(ctx, theauth.AuditQuery{})
	if err != nil || len(got) != 1 {
		t.Fatalf("query = %d, %v", len(got), err)
	}
	got[0].Metadata["k"] = "changed"
	got[0].InputProvenance["k"] = "changed"
	got[0].DelegationChain[0] = "changed"
	if res, err := s.VerifyAuditChain(ctx); err != nil || !res.OK {
		t.Fatalf("verify after caller mutation = %+v, %v", res, err)
	}
}

// One bad event in a batch must not leave the earlier events of that batch behind with the chain
// head already advanced, matching the transactional SQL stores.
func TestMemoryAuditBatchIsAtomic(t *testing.T) {
	ctx := context.Background()
	s := New()
	bad := chainEvent("bad")
	bad.Metadata = map[string]any{"c": make(chan int)}
	if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{chainEvent("ok"), bad}); err == nil {
		t.Fatal("unmarshalable metadata accepted")
	}
	if got, _, _ := s.QueryAuditEvents(ctx, theauth.AuditQuery{}); len(got) != 0 {
		t.Fatalf("%d rows left behind by a failed batch", len(got))
	}
	if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{chainEvent("next")}); err != nil {
		t.Fatal(err)
	}
	if res, err := s.VerifyAuditChain(ctx); err != nil || !res.OK || res.Checked != 1 {
		t.Fatalf("verify = %+v, %v", res, err)
	}
}

// A signed head whose row was evicted from the ring is not a forgery and not a truncation. It must
// not be reported as a hash mismatch.
func TestMemoryHeadCheckpointAfterEvictionOfSignedRow(t *testing.T) {
	ctx := context.Background()
	s := New()
	signer, pub, _ := checkpoint.GenerateKeyPair("k")
	for i := 0; i < 5; i++ {
		_ = s.InsertAuditEvents(ctx, []theauth.AuditEvent{chainEvent("a")})
	}
	old, err := checkpoint.CreateHeadCheckpoint(ctx, s, checkpoint.HeadOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < auditRingCap+10; i++ {
		_ = s.InsertAuditEvents(ctx, []theauth.AuditEvent{chainEvent("a")})
	}
	res, err := checkpoint.CheckHeadCheckpoint(ctx, s, old, pub)
	if err != nil || res.Valid || res.Reason != checkpoint.ReasonHeadNotRetained {
		t.Fatalf("evicted head = %+v, %v", res, err)
	}
	fresh, _ := checkpoint.CreateHeadCheckpoint(ctx, s, checkpoint.HeadOptions{Signer: signer})
	if res, err := checkpoint.CheckHeadCheckpoint(ctx, s, fresh, pub); err != nil || !res.Valid {
		t.Fatalf("fresh head = %+v, %v", res, err)
	}
}

func TestMemoryAuditChainConcurrentWritersReadersAndMutators(t *testing.T) {
	ctx := context.Background()
	s := New()
	signer, pub, _ := checkpoint.GenerateKeyPair("k")
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				_ = s.InsertAuditEvents(ctx, []theauth.AuditEvent{chainEvent("a"), chainEvent("b")})
			}
		}()
	}
	for r := 0; r < 2; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				got, _, _ := s.QueryAuditEvents(ctx, theauth.AuditQuery{Limit: 50})
				for _, e := range got {
					e.Metadata["scribble"] = i
				}
				_, _ = s.VerifyAuditChain(ctx)
				if hc, err := checkpoint.CreateHeadCheckpoint(ctx, s, checkpoint.HeadOptions{Signer: signer}); err == nil {
					if res, err := checkpoint.CheckHeadCheckpoint(ctx, s, hc, pub); err != nil || !res.Valid {
						t.Errorf("check = %+v, %v", res, err)
					}
				}
			}
		}()
	}
	wg.Wait()
	if res, err := s.VerifyAuditChain(ctx); err != nil || !res.OK || res.Checked != 800 {
		t.Fatalf("verify = %+v, %v", res, err)
	}
}
