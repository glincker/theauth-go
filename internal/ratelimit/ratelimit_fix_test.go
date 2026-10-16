package ratelimit

import (
	"testing"
	"time"
)

func TestNewWithClampsInvalidArgs(t *testing.T) {
	tests := []struct {
		name        string
		perMinute   int
		evictAfter  time.Duration
		tickerEvery time.Duration
	}{
		{"zero per minute", 0, time.Minute, time.Minute},
		{"negative per minute", -5, time.Minute, time.Minute},
		{"zero ticker", 5, time.Minute, 0},
		{"negative ticker", 5, time.Minute, -time.Second},
		{"zero evict", 5, 0, time.Minute},
		{"all invalid", 0, -1, -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k := NewWith(tc.perMinute, tc.evictAfter, tc.tickerEvery)
			defer k.Stop()
			if !k.Allow("a") {
				t.Fatal("first request must be allowed with clamped defaults")
			}
			if k.perMinute <= 0 || k.tickerEvery <= 0 || k.evictAfter <= 0 {
				t.Fatalf("not clamped: %d %v %v", k.perMinute, k.tickerEvery, k.evictAfter)
			}
		})
	}
}

func TestGCEvictsStaleKeysOnly(t *testing.T) {
	k := NewWith(5, 20*time.Millisecond, 5*time.Millisecond)
	defer k.Stop()
	k.Allow("stale")
	time.Sleep(60 * time.Millisecond)
	k.Allow("fresh")
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && k.EntryCount() > 1 {
		time.Sleep(5 * time.Millisecond)
	}
	k.mu.RLock()
	_, stale := k.limits["stale"]
	k.mu.RUnlock()
	if stale {
		t.Fatal("stale key not evicted")
	}
}
