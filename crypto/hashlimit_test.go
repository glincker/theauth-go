package crypto

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHashSlotsBoundConcurrency(t *testing.T) {
	SetHashConcurrency(2)
	t.Cleanup(func() { SetHashConcurrency(0) })

	var running, peak atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release := acquireHashSlot()
			n := running.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			running.Add(-1)
			release()
		}()
	}
	wg.Wait()
	if got := peak.Load(); got != 2 {
		t.Fatalf("peak concurrent holders = %d, want 2", got)
	}
}

func TestSetHashConcurrencyDefault(t *testing.T) {
	SetHashConcurrency(-1)
	if got := cap(*hashSlots.Load()); got != DefaultHashConcurrency() || got < 1 {
		t.Fatalf("cap = %d, want default %d", got, DefaultHashConcurrency())
	}
}
