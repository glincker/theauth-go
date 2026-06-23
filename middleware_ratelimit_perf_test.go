package theauth_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
)

// BenchmarkRateLimitReadHeavy measures the Allow hot path under read-heavy
// conditions: all keys already exist so every call takes the shared RLock
// path (perf re-audit 2026-06-21, item 2). The benchmark is informational;
// CI does not gate on benchmark numbers.
func BenchmarkRateLimitReadHeavy(b *testing.B) {
	const numKeys = 100
	const perMinute = 10000 // high limit so Allow always returns true

	lim := theauth.NewKeyedLimiterForTest(perMinute, time.Hour, time.Hour)
	b.Cleanup(lim.Stop)

	// Pre-populate the map so every b.N iteration hits the fast RLock path.
	keys := make([]string, numKeys)
	for i := 0; i < numKeys; i++ {
		keys[i] = fmt.Sprintf("192.0.2.%d", i)
		lim.Allow(keys[i])
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			lim.Allow(keys[i%numKeys])
			i++
		}
	})
}

// TestRateLimitConcurrentReaders ensures the race detector finds no data
// races when many goroutines concurrently call Allow on pre-existing keys
// (exercising the shared RLock path) alongside occasional inserts of new
// keys (exercising the write-lock path) (perf re-audit 2026-06-21, item 2).
func TestRateLimitConcurrentReaders(t *testing.T) {
	t.Parallel()
	const existing = 20
	const newKeys = 10
	const readers = 50
	const perMinute = 10000

	lim := theauth.NewKeyedLimiterForTest(perMinute, time.Hour, time.Hour)
	t.Cleanup(lim.Stop)

	// Seed existing keys.
	for i := 0; i < existing; i++ {
		lim.Allow(fmt.Sprintf("10.0.0.%d", i))
	}

	var wg sync.WaitGroup
	// Concurrent readers on existing keys.
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("10.0.0.%d", i%existing)
			for j := 0; j < 100; j++ {
				lim.Allow(key)
			}
		}(i)
	}
	// Concurrent writers inserting new keys.
	for i := 0; i < newKeys; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lim.Allow(fmt.Sprintf("172.16.%d.1", i))
		}(i)
	}
	wg.Wait()
}
