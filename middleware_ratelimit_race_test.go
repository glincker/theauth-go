package theauth_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
)

// TestRateLimiterConcurrentSameIP spawns N goroutines that all hit the
// same key against a limiter configured for 5 per minute. The 5 token
// burst budget must be honored: exactly 5 must pass, the rest must be
// rejected, with no lost increments under contention.
func TestRateLimiterConcurrentSameIP(t *testing.T) {
	t.Parallel()
	const total = 1000
	const limit = 5

	lim := theauth.NewKeyedLimiterForTest(limit, time.Hour, time.Hour)
	t.Cleanup(lim.Stop)

	var passes int64
	var wg sync.WaitGroup
	wg.Add(total)
	for i := 0; i < total; i++ {
		go func() {
			defer wg.Done()
			if lim.Allow("198.51.100.1") {
				atomic.AddInt64(&passes, 1)
			}
		}()
	}
	wg.Wait()

	got := atomic.LoadInt64(&passes)
	if got != limit {
		t.Fatalf("passes = %d, want %d under same-IP contention", got, limit)
	}
}

// TestRateLimiterConcurrentDifferentIPs spawns goroutines across 50
// distinct keys with a 5 per minute limit. Each key must accumulate
// exactly 5 passes, independently of any other key.
func TestRateLimiterConcurrentDifferentIPs(t *testing.T) {
	t.Parallel()
	const ipCount = 50
	const perIP = 100
	const limit = 5

	lim := theauth.NewKeyedLimiterForTest(limit, time.Hour, time.Hour)
	t.Cleanup(lim.Stop)

	var (
		mu     sync.Mutex
		passes = make(map[string]int, ipCount)
	)
	var wg sync.WaitGroup
	wg.Add(ipCount * perIP)
	for i := 0; i < ipCount; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		for j := 0; j < perIP; j++ {
			go func(ip string) {
				defer wg.Done()
				if lim.Allow(ip) {
					mu.Lock()
					passes[ip]++
					mu.Unlock()
				}
			}(ip)
		}
	}
	wg.Wait()

	for i := 0; i < ipCount; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		if got := passes[ip]; got != limit {
			t.Fatalf("ip %s: passes = %d, want %d (independent buckets)", ip, got, limit)
		}
	}
}
