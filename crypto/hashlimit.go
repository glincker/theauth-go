package crypto

import (
	"runtime"
	"sync/atomic"
)

// hashSlots bounds concurrent Argon2id computations. Each one allocates
// argonMemoryKiB and keeps argonThreads cores busy, so without a bound a
// burst of logins multiplies memory (128 concurrent sign-ins measured at
// 7.5 GB RSS) while adding no throughput, since the cores are already full.
var hashSlots atomic.Pointer[chan struct{}]

// DefaultHashConcurrency is NumCPU divided by the Argon2id thread count,
// at least 1: enough to keep every core busy without queueing memory.
func DefaultHashConcurrency() int {
	return max(1, runtime.NumCPU()/argonThreads)
}

// SetHashConcurrency bounds how many Argon2id hashes or verifications run at
// once; further callers wait their turn. n <= 0 restores the default.
// Computations already running finish under the previous bound.
func SetHashConcurrency(n int) {
	if n <= 0 {
		n = DefaultHashConcurrency()
	}
	ch := make(chan struct{}, n)
	hashSlots.Store(&ch)
}

func acquireHashSlot() (release func()) {
	p := hashSlots.Load()
	if p == nil {
		SetHashConcurrency(0)
		p = hashSlots.Load()
	}
	ch := *p
	ch <- struct{}{}
	return func() { <-ch }
}
