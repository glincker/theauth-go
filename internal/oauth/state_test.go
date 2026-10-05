package oauth

import (
	"context"
	"errors"
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
