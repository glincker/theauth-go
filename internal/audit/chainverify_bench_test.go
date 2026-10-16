package audit

import (
	"fmt"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// buildBenchChain returns n linked rows of one chain, with raw subject and
// actor ids set so VerifyChainRows exercises the pseudonym comparison too.
func buildBenchChain(b *testing.B, n int, secret []byte) []ChainRow {
	b.Helper()
	rows := make([]ChainRow, 0, n)
	head := ChainHead{}
	base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		e := models.AuditEvent{
			ID:         ulid.New(),
			Action:     "agent.authorize",
			TargetType: "tool",
			TargetID:   fmt.Sprintf("t%d", i),
			Metadata:   map[string]any{"i": i},
			IP:         "203.0.113.7",
			UserAgent:  "bench",
			CreatedAt:  base.Add(time.Duration(i) * time.Millisecond),
			SubjectID:  "user_1",
			ActorID:    "agent_9",
		}
		entry, err := BuildChainEntry(e, secret, head)
		if err != nil {
			b.Fatal(err)
		}
		rows = append(rows, ChainRow{
			Payload:    entry.Payload,
			Hash:       entry.Hash,
			RawSubject: e.SubjectID,
			RawActor:   e.ActorID,
		})
		head = ChainHead{Seq: entry.Payload.Seq, Hash: entry.Hash}
	}
	return rows
}

// BenchmarkChainVerify measures a full walk of a 1000-row chain, the work a
// backend does per VerifyAuditChain call once rows are scanned. Reported per
// op is the whole walk, so divide by 1000 for a per-row cost.
func BenchmarkChainVerify(b *testing.B) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	rows := buildBenchChain(b, 1000, secret)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := 0
		res, err := VerifyChainRows(func() (ChainRow, bool, error) {
			if idx >= len(rows) {
				return ChainRow{}, false, nil
			}
			r := rows[idx]
			idx++
			return r, true, nil
		}, secret, 0)
		if err != nil || !res.OK || res.Checked != len(rows) {
			b.Fatalf("verify failed: res=%+v err=%v", res, err)
		}
	}
}
