package audit

import (
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	oklog "github.com/oklog/ulid/v2"
)

// The golden event and secret are mirrored in the sqlite, postgres and mysql tests, which assert
// the same stored hash.
func goldenEvent(t *testing.T) models.AuditEvent {
	t.Helper()
	id, err := oklog.Parse("01JAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	return models.AuditEvent{
		ID: id, Action: "agent.authorize", TargetType: "tool", TargetID: "t1",
		Metadata: map[string]any{"b": 2, "a": "x"}, IP: "203.0.113.7", UserAgent: "golden",
		CreatedAt: time.UnixMicro(1760000000123456), SubjectID: "user_1", ActorID: "agent_9",
		PolicyVersion: "v7", ApproverID: "user_2", DelegationChain: []string{"agent_1", "agent_9"},
		InputProvenance: map[string]any{"source": "tool_output"},
	}
}

const (
	goldenSecret   = "0123456789abcdef0123456789abcdef"
	goldenHashWant = "725905a7b0acf9e2066f9dfda03a95db25fa4797aceab17401144b6427ae14fe"
)

func TestChainHashGoldenVector(t *testing.T) {
	entry, err := BuildChainEntry(goldenEvent(t), []byte(goldenSecret), ChainHead{})
	if err != nil {
		t.Fatal(err)
	}
	if entry.Hash != goldenHashWant {
		t.Fatalf("golden hash = %s", entry.Hash)
	}
	if entry.Payload.Seq != 1 || entry.Payload.Prev != "" || entry.Metadata != `{"a":"x","b":2}` {
		t.Fatalf("unexpected entry: %+v", entry)
	}
	next, err := BuildChainEntry(goldenEvent(t), []byte(goldenSecret), ChainHead{Seq: 1, Hash: entry.Hash})
	if err != nil || next.Payload.Seq != 2 || next.Payload.Prev != entry.Hash || next.Hash == entry.Hash {
		t.Fatalf("link wrong: %+v, %v", next, err)
	}
}

func TestVerifyChainRowsDetectsBreaks(t *testing.T) {
	secret := []byte(goldenSecret)
	build := func(n int) []ChainRow {
		var rows []ChainRow
		head := ChainHead{}
		for i := 0; i < n; i++ {
			e, err := BuildChainEntry(goldenEvent(t), secret, head)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, ChainRow{Payload: e.Payload, Hash: e.Hash, RawSubject: "user_1", RawActor: "agent_9", RawApprover: "user_2"})
			head = ChainHead{Seq: e.Payload.Seq, Hash: e.Hash}
		}
		return rows
	}
	run := func(rows []ChainRow) models.AuditChainResult {
		i := 0
		res, err := VerifyChainRows(func() (ChainRow, bool, error) {
			if i >= len(rows) {
				return ChainRow{}, false, nil
			}
			i++
			return rows[i-1], true, nil
		}, secret, 0)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := run(build(3)); !res.OK || res.Checked != 3 {
		t.Fatalf("clean chain = %+v", res)
	}
	rows := build(3)
	rows[1].Payload.Action = "tampered"
	if res := run(rows); res.OK || res.FirstBreak.Reason != "hash_mismatch" || res.FirstBreak.Seq != 2 {
		t.Fatalf("tamper = %+v", res)
	}
	rows = build(3)
	rows = append(rows[:1], rows[2:]...)
	if res := run(rows); res.OK || res.FirstBreak.Reason != "seq_gap" {
		t.Fatalf("gap = %+v", res)
	}
	rows = build(2)
	rows[0].RawSubject = "user_X"
	if res := run(rows); res.OK || res.FirstBreak.Reason != "pseudonym_mismatch" {
		t.Fatalf("pseudonym = %+v", res)
	}
	rows = build(2)
	rows[0].RawSubject, rows[0].RawApprover = "", ""
	if res := run(rows); !res.OK || res.Erased != 1 {
		t.Fatalf("erased = %+v", res)
	}
}

// RecordedAtUs and Event are written next to the chain but never hashed, so setting them leaves the
// golden hash of the v1 chain untouched. Rows written before the columns existed keep verifying.
func TestChainHashIgnoresEventAndRecordedAtUs(t *testing.T) {
	ev := goldenEvent(t)
	ev.Event = EventAuthorize
	ev.RecordedAtUs = 1760000000999999
	entry, err := BuildChainEntry(ev, []byte(goldenSecret), ChainHead{})
	if err != nil {
		t.Fatal(err)
	}
	if entry.Hash != goldenHashWant {
		t.Fatalf("hash changed when Event and RecordedAtUs were set: %s", entry.Hash)
	}
}
