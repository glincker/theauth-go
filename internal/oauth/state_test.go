package oauth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStateStoreSingleUseAndExpiry(t *testing.T) {
	m := NewMemoryStateStore()
	t.Cleanup(m.Close)
	ctx := context.Background()

	if err := m.Put(ctx, "a", State{Provider: "p"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if st, err := m.Take(ctx, "a"); err != nil || st.Provider != "p" {
		t.Fatalf("first take: %+v %v", st, err)
	}
	if _, err := m.Take(ctx, "a"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("second take must fail, got %v", err)
	}

	_ = m.Put(ctx, "exp", State{}, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, err := m.Take(ctx, "exp"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("expired take must fail, got %v", err)
	}
}

func TestMemoryStateStoreSweepDropsExpired(t *testing.T) {
	m := NewMemoryStateStore()
	t.Cleanup(m.Close)
	ctx := context.Background()
	_ = m.Put(ctx, "old", State{}, time.Millisecond)
	_ = m.Put(ctx, "live", State{}, time.Minute)
	time.Sleep(5 * time.Millisecond)
	m.Sweep()
	if m.Len() != 1 {
		t.Fatalf("want 1 entry after sweep, got %d", m.Len())
	}
}

func TestMatchReturnTo(t *testing.T) {
	allow := []string{"/dash", "/app/*", "https://app.example.com/ok", "https://app.example.com/area/*"}
	tests := []struct{ in, want string }{
		{"/dash", "/dash"},
		{"/dash/x", ""},
		{"/app/", "/app/"},
		{"/app/a/b", "/app/a/b"},
		{"https://app.example.com/ok", "https://app.example.com/ok"},
		{"https://app.example.com/ok/", ""},
		{"https://app.example.com/area/z", "https://app.example.com/area/z"},
		{"https://app.example.com.evil.io/area/z", ""},
		{"//evil.com/app/x", ""},
		{"/app/\\evil", ""},
		{"/app/x\r\nSet-Cookie: a=b", ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := MatchReturnTo(tc.in, allow); got != tc.want {
			t.Errorf("MatchReturnTo(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if MatchReturnTo("/dash", nil) != "" {
		t.Error("empty allow-list must reject everything")
	}
}

func TestMatchReturnToRejectsControlChars(t *testing.T) {
	allow := []string{"/*"}
	tests := []struct{ name, in string }{
		{"tab", "/\t/evil.com"},
		{"newline", "/\n/evil.com"},
		{"carriage return", "/\r/evil.com"},
		{"nul", "/\x00/evil.com"},
		{"del", "/\x7f/evil.com"},
		{"escape", "/\x1b/evil.com"},
		{"backslash", "/\\evil.com"},
		{"trailing tab", "/ok\t"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchReturnTo(tc.in, allow); got != "" {
				t.Fatalf("MatchReturnTo(%q) = %q, want rejection", tc.in, got)
			}
		})
	}
	for _, ok := range []string{"/dash", "/a/b?x=1&y=2", "/%2F/evil.com"} {
		if got := MatchReturnTo(ok, allow); got != ok {
			t.Fatalf("MatchReturnTo(%q) = %q, want it kept", ok, got)
		}
	}
}

func TestHasUnsafeRedirectChars(t *testing.T) {
	for in, want := range map[string]bool{
		"": false, "/ok": false, "/a?b=c": false, "https://x.example/p": false,
		"/\t/x": true, "a\nb": true, "a\x00": true, "a\x7f": true, "/\\x": true,
	} {
		if got := HasUnsafeRedirectChars(in); got != want {
			t.Errorf("HasUnsafeRedirectChars(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestMemoryStateStoreTakeSingleWinner takes one state entry from many goroutines at once. The
// callback must see a state exactly once, otherwise one authorization response could be replayed.
func TestMemoryStateStoreTakeSingleWinner(t *testing.T) {
	m := NewMemoryStateStore()
	t.Cleanup(m.Close)
	ctx := context.Background()
	if err := m.Put(ctx, "race-key", State{}, time.Minute); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := m.Take(ctx, "race-key"); err == nil {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("DOUBLE SPEND: %d Take calls returned one state, want 1", wins.Load())
	}
}
