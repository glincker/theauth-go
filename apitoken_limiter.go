package theauth

import (
	"sync"
	"time"
)

// attemptLimiter counts failures per key inside a sliding window.
type attemptLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newAttemptLimiter(max int, window time.Duration) *attemptLimiter {
	return &attemptLimiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func (l *attemptLimiter) prune(key string, now time.Time) []time.Time {
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.hits, key)
		return nil
	}
	l.hits[key] = kept
	return kept
}

// blocked reports whether key has used up its failure budget.
func (l *attemptLimiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key, now)) >= l.max
}

func (l *attemptLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(key, now)
	l.hits[key] = append(l.hits[key], now)
}
