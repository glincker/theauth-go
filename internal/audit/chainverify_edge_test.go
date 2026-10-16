package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// chainOf builds a verified chain of n rows for one key with the given secret.
func chainOf(t *testing.T, key string, n int, secret []byte) []ChainRow {
	t.Helper()
	rows := make([]ChainRow, 0, n)
	head := ChainHead{}
	// One organization per call keeps every row of the chain under one chain key.
	var org *models.ULID
	if key != "" {
		o := ulid.New()
		org = &o
	}
	for i := 0; i < n; i++ {
		e := models.AuditEvent{
			ID: ulid.New(), Action: "a", TargetType: "t", TargetID: "x",
			CreatedAt: time.UnixMicro(1760000000000000 + int64(i)),
			SubjectID: "sub", ActorID: "act", OrganizationID: org,
		}
		entry, err := BuildChainEntry(e, secret, head)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, ChainRow{Payload: entry.Payload, Hash: entry.Hash, RawSubject: "sub", RawActor: "act"})
		head = ChainHead{Seq: entry.Payload.Seq, Hash: entry.Hash}
	}
	return rows
}

func runVerify(t *testing.T, rows []ChainRow, secret []byte) (res models.AuditChainResult) {
	t.Helper()
	i := 0
	res, err := VerifyChainRows(func() (ChainRow, bool, error) {
		if i >= len(rows) {
			return ChainRow{}, false, nil
		}
		i++
		return rows[i-1], true, nil
	}, secret, 2)
	if err != nil {
		t.Fatalf("VerifyChainRows: %v", err)
	}
	return res
}

// TestVerifyChainRowsEdgeCases walks tampered and malformed chains and checks
// the reported break reason and position for each.
func TestVerifyChainRowsEdgeCases(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tests := []struct {
		name       string
		mutate     func(rows []ChainRow) []ChainRow
		wantOK     bool
		wantReason string
		wantSeq    int64
	}{
		{"empty input verifies", func(rows []ChainRow) []ChainRow { return nil }, true, "", 0},
		{"intact chain verifies", func(rows []ChainRow) []ChainRow { return rows }, true, "", 0},
		{"dropped middle row is a seq gap", func(rows []ChainRow) []ChainRow {
			return append(append([]ChainRow{}, rows[:1]...), rows[2:]...)
		}, false, "seq_gap", 3},
		{"first row not seq 1", func(rows []ChainRow) []ChainRow {
			r := rows[0]
			r.Payload.Seq = 2
			return []ChainRow{r}
		}, false, "seq_gap", 2},
		{"altered prev link", func(rows []ChainRow) []ChainRow {
			out := append([]ChainRow{}, rows...)
			out[1].Payload.Prev = "deadbeef"
			return out
		}, false, "prev_hash_mismatch", 2},
		{"altered payload fails hash", func(rows []ChainRow) []ChainRow {
			out := append([]ChainRow{}, rows...)
			out[2].Payload.Action = "forged"
			return out
		}, false, "hash_mismatch", 3},
		{"raw subject edited is pseudonym mismatch", func(rows []ChainRow) []ChainRow {
			out := append([]ChainRow{}, rows...)
			out[0].RawSubject = "someone_else"
			return out
		}, false, "pseudonym_mismatch", 1},
		{"erased raw id still verifies", func(rows []ChainRow) []ChainRow {
			out := append([]ChainRow{}, rows...)
			out[0].RawSubject = ""
			out[0].RawActor = ""
			return out
		}, true, "", 0},
		{"backend extra break is reported", func(rows []ChainRow) []ChainRow {
			out := append([]ChainRow{}, rows...)
			out[0].ExtraBreak = "hash_mismatch"
			return out
		}, false, "hash_mismatch", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := tt.mutate(chainOf(t, "org", 3, secret))
			res := runVerify(t, rows, secret)
			if res.OK != tt.wantOK {
				t.Fatalf("OK = %v, want %v (res=%+v)", res.OK, tt.wantOK, res)
			}
			if res.Unchained != 2 {
				t.Fatalf("Unchained = %d, want passthrough 2", res.Unchained)
			}
			if tt.wantOK {
				return
			}
			if res.FirstBreak == nil {
				t.Fatal("FirstBreak is nil")
			}
			if res.FirstBreak.Reason != tt.wantReason || res.FirstBreak.Seq != tt.wantSeq {
				t.Fatalf("break = %q at seq %d, want %q at %d", res.FirstBreak.Reason, res.FirstBreak.Seq, tt.wantReason, tt.wantSeq)
			}
		})
	}
}

// TestVerifyChainRowsResetsPerChain checks that a second chain starts again at
// seq 1 with an empty previous hash, so two valid chains interleave cleanly.
func TestVerifyChainRowsResetsPerChain(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	a := chainOf(t, "a", 2, secret)
	b := chainOf(t, "b", 2, secret)
	rows := append(append([]ChainRow{}, a...), b...)
	res := runVerify(t, rows, secret)
	if !res.OK || res.Checked != 4 {
		t.Fatalf("res = %+v, want OK with 4 checked", res)
	}
}

// TestServiceEmitBeforeStartAndAfterStop covers the lifecycle edges: emit is
// rejected before Start, Start is idempotent, and emit after Stop is rejected
// without panicking.
func TestServiceEmitBeforeStartAndAfterStop(t *testing.T) {
	st := &recordingStore{}
	s := NewService(st, Config{BufferSize: 8, BatchSize: 4, FlushInterval: time.Millisecond, DrainTimeout: time.Second})
	if err := s.emit(context.Background(), "x.y", models.TargetRef{}, nil, nil, nil); err != ErrAuditUnavailable {
		t.Fatalf("emit before Start = %v, want ErrAuditUnavailable", err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	if err := s.emit(context.Background(), "x.y", models.TargetRef{}, nil, nil, nil); err != nil {
		t.Fatalf("emit after Start: %v", err)
	}
	s.Stop()
	s.Stop()
	if err := s.emit(context.Background(), "x.y", models.TargetRef{}, nil, nil, nil); err != ErrAuditUnavailable {
		t.Fatalf("emit after Stop = %v, want ErrAuditUnavailable", err)
	}
	if got := st.count(); got != 1 {
		t.Fatalf("written events = %d, want 1 drained before Stop returned", got)
	}
}

// TestServiceConcurrentEmitAndStart exercises the Start/emit ordering that the
// channel-in-constructor change fixed. Run with -race.
func TestServiceConcurrentEmitAndStart(t *testing.T) {
	st := &recordingStore{}
	s := NewService(st, Config{BufferSize: 64, BatchSize: 8, FlushInterval: time.Millisecond, DrainTimeout: time.Second})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = s.emit(context.Background(), "x.y", models.TargetRef{}, nil, nil, nil)
			}
		}()
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	s.Stop()
}

// recordingStore is an in-memory Storage that counts inserted events.
type recordingStore struct {
	mu sync.Mutex
	n  int
}

func (r *recordingStore) InsertAuditEvents(_ context.Context, evs []models.AuditEvent) error {
	r.mu.Lock()
	r.n += len(evs)
	r.mu.Unlock()
	return nil
}

func (r *recordingStore) QueryAuditEvents(context.Context, models.AuditQuery) ([]models.AuditEvent, string, error) {
	return nil, "", nil
}

func (r *recordingStore) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}
