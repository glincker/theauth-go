package checkpoint

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

type fakeEvents []models.AuditEvent

func (f fakeEvents) QueryAuditEvents(context.Context, models.AuditQuery) ([]models.AuditEvent, string, error) {
	return append([]models.AuditEvent(nil), f...), "", nil
}

func hashOf(n int) string {
	const hexd = "0123456789abcdef"
	b := make([]byte, 64)
	for i := range b {
		b[i] = hexd[(n+i)%16]
	}
	return string(b)
}

func globalChain(n int) fakeEvents {
	out := fakeEvents{}
	for i := 1; i <= n; i++ {
		out = append(out, models.AuditEvent{ID: ulid.New(), ChainSeq: uint64(i), Hash: hashOf(i)})
	}
	return out
}

func TestHeadCheckpointRoundTrip(t *testing.T) {
	ctx := context.Background()
	signer, pub, err := GenerateKeyPair("k1")
	if err != nil {
		t.Fatal(err)
	}
	org := ulid.New()
	log := append(globalChain(3), models.AuditEvent{ID: ulid.New(), OrganizationID: &org, ChainSeq: 1, Hash: hashOf(40)})
	hc, err := CreateHeadCheckpoint(ctx, log, HeadOptions{Signer: signer, Now: time.UnixMilli(1760000000000)})
	if err != nil {
		t.Fatal(err)
	}
	if len(hc.Heads) != 2 || hc.Heads[0].ChainKey != "" || hc.Heads[0].Seq != 3 || hc.Heads[1].ChainKey != org.String() {
		t.Fatalf("heads = %+v", hc.Heads)
	}
	if o := VerifyHeadCheckpoint(hc, pub); !o.Valid {
		t.Fatalf("verify = %+v", o)
	}
	if res, err := CheckHeadCheckpoint(ctx, log, hc, pub); err != nil || !res.Valid {
		t.Fatalf("check = %+v, %v", res, err)
	}
	// Appending is fine.
	longer := append(log, models.AuditEvent{ID: ulid.New(), ChainSeq: 4, Hash: hashOf(4)})
	if res, err := CheckHeadCheckpoint(ctx, longer, hc, pub); err != nil || !res.Valid {
		t.Fatalf("check after append = %+v, %v", res, err)
	}
}

func TestHeadCheckpointDetectsLoss(t *testing.T) {
	ctx := context.Background()
	signer, pub, _ := GenerateKeyPair("k1")
	log := globalChain(4)
	hc, err := CreateHeadCheckpoint(ctx, log, HeadOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := CheckHeadCheckpoint(ctx, log[:3], hc, pub); res.Valid || res.Reason != ReasonChainTruncated {
		t.Fatalf("truncated = %+v", res)
	}
	if res, _ := CheckHeadCheckpoint(ctx, fakeEvents{}, hc, pub); res.Valid || res.Reason != ReasonChainTruncated {
		t.Fatalf("empty = %+v", res)
	}
	rewritten := append(fakeEvents(nil), log...)
	rewritten[3].Hash = hashOf(99)
	if res, _ := CheckHeadCheckpoint(ctx, rewritten, hc, pub); res.Valid || res.Reason != ReasonHeadMismatch {
		t.Fatalf("rewritten = %+v", res)
	}
}

func TestHeadCheckpointRejectsBadSignatures(t *testing.T) {
	ctx := context.Background()
	signer, pub, _ := GenerateKeyPair("k1")
	_, otherPub, _ := GenerateKeyPair("k1")
	hc, _ := CreateHeadCheckpoint(ctx, globalChain(2), HeadOptions{Signer: signer})
	cases := []struct {
		name string
		edit func(h *HeadCheckpoint)
		keys []PublicKey
		want Reason
	}{
		{"seq", func(h *HeadCheckpoint) { h.Heads[0].Seq = 1 }, []PublicKey{pub}, ReasonBadSignature},
		{"timestamp", func(h *HeadCheckpoint) { h.Timestamp++ }, []PublicKey{pub}, ReasonBadSignature},
		{"wrong key", func(h *HeadCheckpoint) {}, []PublicKey{otherPub}, ReasonBadSignature},
		{"unknown key", func(h *HeadCheckpoint) { h.KeyID = "zz" }, []PublicKey{pub}, ReasonUnknownKey},
		{"alg", func(h *HeadCheckpoint) { h.Alg = "none" }, []PublicKey{pub}, ReasonUnsupportedAlg},
		{"bad hash", func(h *HeadCheckpoint) { h.Heads[0].Hash = "zz" }, []PublicKey{pub}, ReasonMalformed},
		{"nil heads", func(h *HeadCheckpoint) { h.Heads = nil }, []PublicKey{pub}, ReasonMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := hc
			h.Heads = append([]ChainHead(nil), hc.Heads...)
			tc.edit(&h)
			if o := VerifyHeadCheckpoint(h, tc.keys...); o.Valid || o.Reason != tc.want {
				t.Fatalf("outcome = %+v, want %s", o, tc.want)
			}
		})
	}
}

func TestHeadCheckpointEmptyLogAndJSON(t *testing.T) {
	ctx := context.Background()
	signer, pub, _ := GenerateKeyPair("k1")
	hc, err := CreateHeadCheckpoint(ctx, fakeEvents{}, HeadOptions{Signer: signer})
	if err != nil || len(hc.Heads) != 0 {
		t.Fatalf("hc = %+v, %v", hc, err)
	}
	if o := VerifyHeadCheckpoint(hc, pub); !o.Valid {
		t.Fatalf("empty verify = %+v", o)
	}
	var back HeadCheckpoint
	raw := []byte(`{"version":1,"alg":"Ed25519","keyId":"k1","timestamp":1}`)
	if err := back.UnmarshalJSON(raw); err == nil {
		t.Fatal("missing heads accepted")
	}
}
