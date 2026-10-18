package memory

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/audit/checkpoint"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storagetest"
)

func chainEvent(action string) theauth.AuditEvent {
	return theauth.AuditEvent{ID: ulid.New(), Action: action, CreatedAt: time.Now(), SubjectID: "user_1",
		Metadata: map[string]any{"k": "v"}}
}

func TestMemoryAuditChainContract(t *testing.T) {
	storagetest.RunAuditChain(t, New())
}

func TestMemoryAuditProvenanceContract(t *testing.T) {
	storagetest.RunAuditProvenance(t, New())
}

func TestMemoryAuditRotationContract(t *testing.T) {
	storagetest.RunAuditRotation(t, New())
}

// dropGlobalTail removes the highest seq row of the global chain, as an attacker with write access
// to the log would.
func dropGlobalTail(s *Store) func(context.Context) error {
	return func(context.Context) error {
		v := s.auditState()
		v.mu.Lock()
		defer v.mu.Unlock()
		best := -1
		for i, e := range v.auditRing {
			if e.OrganizationID == nil && (best < 0 || e.ChainSeq > v.auditRing[best].ChainSeq) {
				best = i
			}
		}
		v.auditRing = append(v.auditRing[:best], v.auditRing[best+1:]...)
		v.auditChain = append(v.auditChain[:best], v.auditChain[best+1:]...)
		return nil
	}
}

func TestMemoryAuditHeadCheckpointContract(t *testing.T) {
	s := New()
	storagetest.RunAuditHeadCheckpoint(t, s, dropGlobalTail(s))
}

func TestMemoryAuditChainDetectsTamper(t *testing.T) {
	cases := []struct {
		name, reason string
		edit         func(v *v10State)
	}{
		{"action", "hash_mismatch", func(v *v10State) { v.auditRing[1].Action = "other" }},
		{"metadata", "hash_mismatch", func(v *v10State) { v.auditRing[1].Metadata["k"] = "x" }},
		{"hash", "hash_mismatch", func(v *v10State) { v.auditRing[1].Hash = "00" }},
		{"raw subject", "pseudonym_mismatch", func(v *v10State) { v.auditRing[1].SubjectID = "user_2" }},
		{"stored session", "hash_mismatch", func(v *v10State) { v.auditChain[1].Payload.ActorSession = "z" }},
		{"seq", "seq_gap", func(v *v10State) { v.auditChain[2].Payload.Seq = 9 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := New()
			for i := 0; i < 3; i++ {
				if err := s.InsertAuditEvents(context.Background(), []theauth.AuditEvent{chainEvent("a")}); err != nil {
					t.Fatal(err)
				}
			}
			res, err := s.VerifyAuditChain(context.Background())
			if err != nil || !res.OK || res.Checked != 3 {
				t.Fatalf("verify = %+v, %v", res, err)
			}
			v := s.auditState()
			v.mu.Lock()
			tc.edit(v)
			v.mu.Unlock()
			res, err = s.VerifyAuditChain(context.Background())
			if err != nil || res.OK || res.FirstBreak == nil || res.FirstBreak.Reason != tc.reason {
				t.Fatalf("tamper not detected: %+v, %v (break %+v)", res, err, res.FirstBreak)
			}
		})
	}
}

func TestMemoryAuditChainCallerCannotAlterHashedMaps(t *testing.T) {
	s := New()
	ev := chainEvent("a")
	if err := s.InsertAuditEvents(context.Background(), []theauth.AuditEvent{ev}); err != nil {
		t.Fatal(err)
	}
	ev.Metadata["k"] = "changed"
	if res, err := s.VerifyAuditChain(context.Background()); err != nil || !res.OK {
		t.Fatalf("verify = %+v, %v", res, err)
	}
}

func TestMemoryAuditChainVerifiesAfterRingEviction(t *testing.T) {
	s := New()
	const extra = 25
	for i := 0; i < auditRingCap+extra; i++ {
		if err := s.InsertAuditEvents(context.Background(), []theauth.AuditEvent{chainEvent("a")}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := s.VerifyAuditChain(context.Background())
	if err != nil || !res.OK || res.Checked != auditRingCap {
		t.Fatalf("verify = %+v, %v (break %+v)", res, err, res.FirstBreak)
	}
	hc, err := checkpoint.CreateHeadCheckpoint(context.Background(), s, headOpts(t))
	if err != nil || len(hc.Heads) != 1 || hc.Heads[0].Seq != auditRingCap+extra {
		t.Fatalf("head = %+v, %v", hc.Heads, err)
	}
}

func headOpts(t *testing.T) checkpoint.HeadOptions {
	t.Helper()
	signer, _, err := checkpoint.GenerateKeyPair("k")
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint.HeadOptions{Signer: signer}
}
