package audit_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	theauth "github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
)

func TestDefaultRedactorTopLevel(t *testing.T) {
	in := map[string]any{
		"email":    "user@example.test",
		"password": "hunter2",
		"token":    "abc123",
	}
	out := theauth.DefaultRedactor(in)
	if out["password"] != "[REDACTED]" {
		t.Errorf("password not redacted: %v", out["password"])
	}
	if out["token"] != "[REDACTED]" {
		t.Errorf("token not redacted: %v", out["token"])
	}
	if out["email"] != "user@example.test" {
		t.Errorf("email should not be redacted: %v", out["email"])
	}
}

func TestDefaultRedactorCaseInsensitive(t *testing.T) {
	in := map[string]any{
		"Password":      "x",
		"REFRESH_TOKEN": "y",
		"Access_Token":  "z",
	}
	out := theauth.DefaultRedactor(in)
	for k, v := range out {
		if v != "[REDACTED]" {
			t.Errorf("%s: not redacted: %v", k, v)
		}
	}
}

func TestDefaultRedactorNested(t *testing.T) {
	in := map[string]any{
		"oauth": map[string]any{
			"provider":     "github",
			"access_token": "secret",
			"meta": map[string]any{
				"refresh_token": "innersecret",
				"safe":          "fine",
			},
		},
		"list": []any{
			map[string]any{"secret": "x"},
			map[string]any{"safe": "y"},
		},
	}
	out := theauth.DefaultRedactor(in)
	oauth := out["oauth"].(map[string]any)
	if oauth["access_token"] != "[REDACTED]" {
		t.Fatalf("access_token nested not redacted: %v", oauth["access_token"])
	}
	meta := oauth["meta"].(map[string]any)
	if meta["refresh_token"] != "[REDACTED]" {
		t.Fatalf("refresh_token deep-nested not redacted: %v", meta["refresh_token"])
	}
	if meta["safe"] != "fine" {
		t.Fatalf("safe field corrupted: %v", meta["safe"])
	}
	list := out["list"].([]any)
	first := list[0].(map[string]any)
	if first["secret"] != "[REDACTED]" {
		t.Fatalf("secret inside slice not redacted: %v", first["secret"])
	}
	second := list[1].(map[string]any)
	if second["safe"] != "y" {
		t.Fatalf("safe inside slice corrupted: %v", second["safe"])
	}
}

func TestDefaultRedactorNilInput(t *testing.T) {
	if out := theauth.DefaultRedactor(nil); out != nil {
		t.Fatalf("nil input should return nil, got %v", out)
	}
}

func TestEmitAuditAsyncWrites(t *testing.T) {
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store,
		BaseURL: "https://example.test",
		Audit:   &theauth.AuditConfig{BufferSize: 64, BatchSize: 8, FlushInterval: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	for i := 0; i < 50; i++ {
		a.EmitAudit(context.Background(), "user.login", theauth.TargetRef{Type: "user", ID: "abc"}, map[string]any{
			"i": i,
		})
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.Stats().AuditWritten >= 50 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := a.Stats().AuditWritten; got != 50 {
		t.Fatalf("AuditWritten=%d, want 50", got)
	}
	if got := a.Stats().AuditDropped; got != 0 {
		t.Fatalf("unexpected drops: %d", got)
	}
}

func TestEmitAuditDropsOnFullBuffer(t *testing.T) {
	store := &blockingStore{Store: memory.New(), block: make(chan struct{})}
	a, err := theauth.New(theauth.Config{
		Storage: store,
		BaseURL: "https://example.test",
		Audit:   &theauth.AuditConfig{BufferSize: 4, BatchSize: 100, FlushInterval: 10 * time.Second},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		close(store.block)
		a.Close()
	})
	// Fire many more events than buffer + batch can hold; expect drops to count.
	for i := 0; i < 200; i++ {
		a.EmitAudit(context.Background(), "user.login", theauth.TargetRef{Type: "user", ID: "abc"}, nil)
	}
	stats := a.Stats()
	if stats.AuditEmitted == 0 {
		t.Fatal("emitted counter not incremented")
	}
	if stats.AuditDropped == 0 {
		t.Fatal("expected drops under saturated buffer with blocked writer")
	}
	if stats.AuditEmitted < stats.AuditWritten+stats.AuditDropped {
		t.Fatalf("emitted (%d) < written (%d) + dropped (%d)", stats.AuditEmitted, stats.AuditWritten, stats.AuditDropped)
	}
}

func TestEmitAuditConcurrent(t *testing.T) {
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store,
		BaseURL: "https://example.test",
		Audit:   &theauth.AuditConfig{BufferSize: 1024, BatchSize: 50, FlushInterval: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	var wg sync.WaitGroup
	const goroutines = 50
	const perGoroutine = 200
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				a.EmitAudit(context.Background(), "user.login", theauth.TargetRef{Type: "user", ID: "x"}, map[string]any{
					"g": id, "i": i,
				})
			}
		}(g)
	}
	wg.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s := a.Stats()
		if s.AuditWritten+s.AuditDropped+s.AuditFailed >= uint64(goroutines*perGoroutine) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	s := a.Stats()
	if s.AuditEmitted != uint64(goroutines*perGoroutine) {
		t.Fatalf("emitted=%d, want %d", s.AuditEmitted, goroutines*perGoroutine)
	}
	if s.AuditEmitted < s.AuditWritten+s.AuditDropped {
		t.Fatalf("invariant broken: emitted=%d, written=%d, dropped=%d", s.AuditEmitted, s.AuditWritten, s.AuditDropped)
	}
}

func TestEmitAuditDrainOnClose(t *testing.T) {
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store,
		BaseURL: "https://example.test",
		Audit:   &theauth.AuditConfig{BufferSize: 1024, BatchSize: 100, FlushInterval: 5 * time.Second, DrainTimeout: 2 * time.Second},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 500; i++ {
		a.EmitAudit(context.Background(), "user.login", theauth.TargetRef{Type: "user", ID: "abc"}, nil)
	}
	a.Close()
	s := a.Stats()
	if s.AuditEmitted != 500 {
		t.Fatalf("emitted=%d, want 500", s.AuditEmitted)
	}
	if s.AuditWritten+s.AuditDropped != 500 {
		t.Fatalf("close should account for every emitted event; written=%d dropped=%d", s.AuditWritten, s.AuditDropped)
	}
}

func TestEmitAuditAsyncContextCancel(t *testing.T) {
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store,
		BaseURL: "https://example.test",
		Audit:   &theauth.AuditConfig{BufferSize: 64, BatchSize: 1, FlushInterval: 5 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	ctx, cancel := context.WithCancel(context.Background())
	a.EmitAudit(ctx, "user.login", theauth.TargetRef{Type: "user", ID: "abc"}, nil)
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.Stats().AuditWritten >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("event canceled with the caller's ctx should still write")
}

// blockingStore wraps memory.Store and blocks InsertAuditEvents on a chan
// for backpressure testing.
type blockingStore struct {
	*memory.Store
	block chan struct{}
	calls atomic.Uint64
}

func (b *blockingStore) InsertAuditEvents(ctx context.Context, events []theauth.AuditEvent) error {
	b.calls.Add(1)
	select {
	case <-b.block:
		return b.Store.InsertAuditEvents(ctx, events)
	case <-ctx.Done():
		return ctx.Err()
	}
}
