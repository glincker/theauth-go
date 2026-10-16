package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// TestKeyedAllowEdges covers the empty-key bypass, burst exhaustion per key,
// and independence between keys.
func TestKeyedAllowEdges(t *testing.T) {
	k := NewWith(3, time.Hour, time.Hour)
	defer k.Stop()
	for i := 0; i < 3; i++ {
		if !k.Allow("a") {
			t.Fatalf("burst call %d for key a denied", i+1)
		}
	}
	if k.Allow("a") {
		t.Fatal("fourth call for key a allowed beyond burst")
	}
	if !k.Allow("b") {
		t.Fatal("key b denied although only key a is exhausted")
	}
	for i := 0; i < 10; i++ {
		if !k.Allow("") {
			t.Fatal("empty key must bypass the limiter")
		}
	}
	if got := k.EntryCount(); got != 2 {
		t.Fatalf("EntryCount = %d, want 2 (empty key creates no entry)", got)
	}
}

// TestKeyedGCEvictsIdleKeys checks that the GC loop drops keys unused for
// longer than evictAfter and keeps recently used ones.
func TestKeyedGCEvictsIdleKeys(t *testing.T) {
	k := NewWith(5, 20*time.Millisecond, 5*time.Millisecond)
	defer k.Stop()
	k.Allow("idle")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if k.EntryCount() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("idle key not evicted, EntryCount = %d", k.EntryCount())
}

// TestKeyedStopIsIdempotent checks that Stop may be called repeatedly and
// that Allow keeps working after it, since only the GC goroutine stops.
func TestKeyedStopIsIdempotent(t *testing.T) {
	k := NewWith(2, time.Hour, time.Hour)
	k.Stop()
	k.Stop()
	if !k.Allow("x") {
		t.Fatal("Allow denied a fresh key after Stop")
	}
}

// TestClientIPTrustedProxyEdges is table driven over the X-Forwarded-For walk.
func TestClientIPTrustedProxyEdges(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	tests := []struct {
		name    string
		remote  string
		xff     []string
		trusted []netip.Prefix
		want    string
	}{
		{"no trusted proxies ignores header", "203.0.113.9:1234", []string{"198.51.100.1"}, nil, "203.0.113.9"},
		{"untrusted peer ignores forged header", "203.0.113.9:1234", []string{"198.51.100.1"}, trusted, "203.0.113.9"},
		{"trusted peer reads rightmost untrusted", "10.0.0.1:443", []string{"198.51.100.7, 10.0.0.2"}, trusted, "198.51.100.7"},
		{"multiple header lines join", "10.0.0.1:443", []string{"198.51.100.7", "10.0.0.2"}, trusted, "198.51.100.7"},
		{"all hops trusted returns leftmost", "10.0.0.1:443", []string{"10.0.0.5, 10.0.0.2"}, trusted, "10.0.0.5"},
		{"malformed hop stops walk at peer", "10.0.0.1:443", []string{"garbage, 10.0.0.2"}, trusted, "10.0.0.1"},
		{"no header from trusted peer", "10.0.0.1:443", nil, trusted, "10.0.0.1"},
		{"v4-mapped hop unmapped", "10.0.0.1:443", []string{"::ffff:198.51.100.7"}, trusted, "198.51.100.7"},
		{"bare remote addr without port", "10.0.0.1", nil, trusted, "10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := ClientIP(r, tt.trusted); got != tt.want {
				t.Fatalf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

// BenchmarkKeyedAllowExisting measures the read-locked fast path for a key
// that already has a limiter, the common case under steady traffic.
func BenchmarkKeyedAllowExisting(b *testing.B) {
	k := NewWith(1<<30, time.Hour, time.Hour)
	defer k.Stop()
	k.Allow("hot")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.Allow("hot")
	}
}
