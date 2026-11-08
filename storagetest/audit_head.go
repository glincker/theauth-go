package storagetest

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/audit/checkpoint"
)

// AuditHeadSuiteStorage is the storage RunAuditHeadCheckpoint needs.
type AuditHeadSuiteStorage interface {
	AuditChainSuiteStorage
}

// RunAuditHeadCheckpoint runs the head checkpoint contract on a chained store: a signed head
// verifies and matches the live log, rows appended later are fine, and cutting rows off the end of
// the global chain is reported even though VerifyAuditChain still passes. dropTail must delete the
// highest seq row of the global chain (the store's own raw delete, as an attacker would).
func RunAuditHeadCheckpoint(t *testing.T, store AuditHeadSuiteStorage, dropTail func(ctx context.Context) error) {
	t.Helper()
	t.Run("AuditHeadCheckpoint", func(t *testing.T) {
		ctx := context.Background()
		signer, pub, err := checkpoint.GenerateKeyPair("head-test")
		if err != nil {
			t.Fatal(err)
		}
		add := func(n int) {
			for i := 0; i < n; i++ {
				if err := store.InsertAuditEvents(ctx, []theauth.AuditEvent{{
					ID: newID(), Action: "storagetest.head", CreatedAt: time.Now(),
				}}); err != nil {
					t.Fatalf("InsertAuditEvents: %v", err)
				}
			}
		}
		add(3)
		hc, err := checkpoint.CreateHeadCheckpoint(ctx, store, checkpoint.HeadOptions{Signer: signer})
		if err != nil {
			t.Fatalf("CreateHeadCheckpoint: %v", err)
		}
		if len(hc.Heads) == 0 {
			t.Fatal("no heads in checkpoint")
		}
		if o := checkpoint.VerifyHeadCheckpoint(hc, pub); !o.Valid {
			t.Fatalf("signature does not verify: %+v", o)
		}
		if res, err := checkpoint.CheckHeadCheckpoint(ctx, store, hc, pub); err != nil || !res.Valid {
			t.Fatalf("fresh check = %+v, %v", res, err)
		}
		add(2)
		if res, err := checkpoint.CheckHeadCheckpoint(ctx, store, hc, pub); err != nil || !res.Valid {
			t.Fatalf("check after append = %+v, %v", res, err)
		}
		newer, err := checkpoint.CreateHeadCheckpoint(ctx, store, checkpoint.HeadOptions{Signer: signer})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := dropTail(ctx); err != nil {
				t.Fatalf("dropTail: %v", err)
			}
		}
		if res := mustVerify(t, store); !res.OK {
			t.Fatalf("a shortened chain still links: %+v", res)
		}
		if res, err := checkpoint.CheckHeadCheckpoint(ctx, store, newer, pub); err != nil || res.Valid ||
			res.Reason != checkpoint.ReasonChainTruncated {
			t.Fatalf("truncation not reported: %+v, %v", res, err)
		}
		forged := hc
		forged.Heads = append([]checkpoint.ChainHead(nil), hc.Heads...)
		forged.Heads[0].Seq++
		if o := checkpoint.VerifyHeadCheckpoint(forged, pub); o.Valid || o.Reason != checkpoint.ReasonBadSignature {
			t.Fatalf("forged head accepted: %+v", o)
		}
	})
}
