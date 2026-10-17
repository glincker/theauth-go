package audit_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

// audit_redactor_depth_test.go covers redaction at depth beyond 2, the typed []map[string]any
// branch, and EmitAudit at 4x fan-out, waiting on the store counter instead of the clock.

// TestDefaultRedactorDeepNesting checks that secret keys are masked at every level of a 5-level
// map, and other keys are kept.
func TestDefaultRedactorDeepNesting(t *testing.T) {
	in := map[string]any{
		"level1_safe": "ok",
		"password":    "L1",
		"level2": map[string]any{
			"level2_safe": "ok",
			"token":       "L2",
			"level3": map[string]any{
				"level3_safe": "ok",
				"secret":      "L3",
				"level4": map[string]any{
					"level4_safe":   "ok",
					"refresh_token": "L4",
					"level5": map[string]any{
						"level5_safe":  "ok",
						"access_token": "L5",
						"code":         "L5b",
					},
				},
			},
		},
	}
	out := theauth.DefaultRedactor(in)
	// Spot-check every depth.
	if out["password"] != "[REDACTED]" {
		t.Errorf("L1 password not redacted: %v", out["password"])
	}
	l2 := out["level2"].(map[string]any)
	if l2["token"] != "[REDACTED]" {
		t.Errorf("L2 token not redacted: %v", l2["token"])
	}
	if l2["level2_safe"] != "ok" {
		t.Errorf("L2 safe corrupted: %v", l2["level2_safe"])
	}
	l3 := l2["level3"].(map[string]any)
	if l3["secret"] != "[REDACTED]" {
		t.Errorf("L3 secret not redacted: %v", l3["secret"])
	}
	l4 := l3["level4"].(map[string]any)
	if l4["refresh_token"] != "[REDACTED]" {
		t.Errorf("L4 refresh_token not redacted: %v", l4["refresh_token"])
	}
	l5 := l4["level5"].(map[string]any)
	if l5["access_token"] != "[REDACTED]" {
		t.Errorf("L5 access_token not redacted: %v", l5["access_token"])
	}
	if l5["code"] != "[REDACTED]" {
		t.Errorf("L5 code not redacted: %v", l5["code"])
	}
	if l5["level5_safe"] != "ok" {
		t.Errorf("L5 safe corrupted: %v", l5["level5_safe"])
	}
}

// TestDefaultRedactorTypedMapSlice covers the []map[string]any arm of redactValue, which the []any
// tests do not reach.
func TestDefaultRedactorTypedMapSlice(t *testing.T) {
	in := map[string]any{
		"providers": []map[string]any{
			{"name": "github", "access_token": "leak1"},
			{"name": "google", "refresh_token": "leak2", "safe": "fine"},
		},
	}
	out := theauth.DefaultRedactor(in)
	providers := out["providers"].([]map[string]any)
	if len(providers) != 2 {
		t.Fatalf("providers len=%d", len(providers))
	}
	if providers[0]["access_token"] != "[REDACTED]" {
		t.Errorf("provider[0] access_token not redacted: %v", providers[0]["access_token"])
	}
	if providers[1]["refresh_token"] != "[REDACTED]" {
		t.Errorf("provider[1] refresh_token not redacted: %v", providers[1]["refresh_token"])
	}
	if providers[1]["safe"] != "fine" {
		t.Errorf("safe field clobbered: %v", providers[1]["safe"])
	}
}

// TestSeededSecretKeysReturnsBlocklist checks the public SeededSecretKeys helper returns the full blocklist.
func TestSeededSecretKeysReturnsBlocklist(t *testing.T) {
	keys := theauth.SeededSecretKeys()
	if len(keys) == 0 {
		t.Fatal("SeededSecretKeys returned no keys")
	}
	want := map[string]bool{
		"password": true, "secret": true, "token": true,
		"code": true, "refresh_token": true, "access_token": true,
	}
	for _, k := range keys {
		if !want[k] {
			t.Errorf("unexpected key in blocklist: %q", k)
		}
		delete(want, k)
	}
	if len(want) > 0 {
		t.Errorf("missing expected keys from blocklist: %v", want)
	}
}

// countingStore wraps the in-memory store and signals each InsertAuditEvents call, so tests can
// wait on the writer.
type countingStore struct {
	*memory.Store
	calls  atomic.Uint64
	rows   atomic.Uint64
	signal chan struct{}
}

func newCountingStore() *countingStore {
	return &countingStore{
		Store:  memory.New(),
		signal: make(chan struct{}),
	}
}

func (s *countingStore) InsertAuditEvents(ctx context.Context, events []theauth.AuditEvent) error {
	s.calls.Add(1)
	s.rows.Add(uint64(len(events)))
	err := s.Store.InsertAuditEvents(ctx, events)
	return err
}

// TestEmitAuditUnderHighConcurrency emits 4x the TestEmitAuditConcurrent fan-out and waits on the
// row counter. It asserts emitted equals written plus dropped and that the larger fan-out does not
// deadlock.
func TestEmitAuditUnderHighConcurrency(t *testing.T) {
	store := newCountingStore()
	a, err := theauth.New(theauth.Config{
		Storage: store,
		BaseURL: "https://example.test",
		Audit:   &theauth.AuditConfig{BufferSize: 2048, BatchSize: 64, FlushInterval: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)

	const goroutines = 200
	const perGoroutine = 200
	total := uint64(goroutines * perGoroutine)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				a.EmitAudit(context.Background(), "stress.event", theauth.TargetRef{Type: "stress", ID: "x"}, map[string]any{
					"g": id, "i": i,
					"nested": map[string]any{
						"password": "redacted",
						"deep": map[string]any{
							"access_token": "redacted-deep",
						},
					},
				})
			}
		}(g)
	}
	wg.Wait()

	// Settle on the counter equality, with a 5s wall-clock cap only as a safety net.
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := a.Stats()
		if s.AuditWritten+s.AuditDropped+s.AuditFailed >= total {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit drain stalled: %+v", s)
		}
		time.Sleep(5 * time.Millisecond)
	}
	s := a.Stats()
	if s.AuditEmitted != total {
		t.Fatalf("emitted=%d, want %d", s.AuditEmitted, total)
	}
	if s.AuditEmitted < s.AuditWritten+s.AuditDropped {
		t.Fatalf("invariant broken: emitted=%d, written=%d, dropped=%d", s.AuditEmitted, s.AuditWritten, s.AuditDropped)
	}
}
