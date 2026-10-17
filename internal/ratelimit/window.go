package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Window is a token bucket budget: Requests events per Per, with Burst as the
// bucket size. Burst defaults to Requests.
type Window struct {
	Requests int
	Per      time.Duration
	Burst    int
}

// Enabled reports whether the window limits anything.
func (w Window) Enabled() bool { return w.Requests > 0 && w.Per > 0 }

func (w Window) normalized() Window {
	if w.Burst <= 0 {
		w.Burst = w.Requests
	}
	return w
}

// refill is how long an idle bucket needs to be full again.
func (w Window) refill() time.Duration {
	if !w.Enabled() {
		return 0
	}
	return w.Per * time.Duration(w.Burst) / time.Duration(w.Requests)
}

// DefaultWindowMaxKeys bounds the number of keys a WindowLimiter tracks.
const DefaultWindowMaxKeys = 10000

// WindowLimiter is a bounded per key token bucket limiter with an injectable
// clock and a Retry-After answer. Each key's bucket remembers the Window it
// was built from; presenting different parameters for the key replaces the
// bucket, so a changed limit takes effect on the next request. Memory is capped
// at maxKeys: when full it first drops keys idle long enough to refill (nothing
// is lost) and then the least recently used key.
type WindowLimiter struct {
	win     Window
	maxKeys int
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]*windowEntry
}

type windowEntry struct {
	win  Window
	lim  *rate.Limiter
	last time.Time
}

// NewWindowLimiter builds a limiter whose default budget is w (possibly
// disabled). now may be nil (time.Now). maxKeys <= 0 uses
// DefaultWindowMaxKeys.
func NewWindowLimiter(w Window, maxKeys int, now func() time.Time) *WindowLimiter {
	if now == nil {
		now = time.Now
	}
	if maxKeys <= 0 {
		maxKeys = DefaultWindowMaxKeys
	}
	return &WindowLimiter{win: w.normalized(), maxKeys: maxKeys, now: now, entries: make(map[string]*windowEntry)}
}

// Allow spends one unit for key under the default budget.
func (l *WindowLimiter) Allow(key string) (bool, time.Duration) {
	return l.take(key, l.win, false)
}

// AllowWith spends one unit for key under w, replacing the key's bucket when w
// differs from the one it was built with.
func (l *WindowLimiter) AllowWith(key string, w Window) (bool, time.Duration) {
	return l.take(key, w.normalized(), false)
}

// AllowCurrent spends one unit for key under the budget the key last used,
// or the default budget for a key not seen yet. Callers that cannot resolve a
// per key override use it so they never reset an overridden bucket.
func (l *WindowLimiter) AllowCurrent(key string) (bool, time.Duration) {
	return l.take(key, l.win, true)
}

func (l *WindowLimiter) take(key string, w Window, keepExisting bool) (bool, time.Duration) {
	if l == nil || key == "" || !w.Enabled() {
		if !keepExisting || l == nil || key == "" {
			return true, 0
		}
	}
	now := l.now()
	l.mu.Lock()
	e, ok := l.entries[key]
	if ok && keepExisting {
		w = e.win
	}
	if !w.Enabled() {
		l.mu.Unlock()
		return true, 0
	}
	if !ok || e.win != w {
		if !ok && len(l.entries) >= l.maxKeys {
			l.evictLocked(now)
		}
		every := w.Per / time.Duration(w.Requests)
		if every <= 0 {
			every = time.Nanosecond
		}
		e = &windowEntry{win: w, lim: rate.NewLimiter(rate.Every(every), w.Burst)}
		l.entries[key] = e
	}
	e.last = now
	l.mu.Unlock()
	r := e.lim.ReserveN(now, 1)
	if !r.OK() {
		return false, w.Per
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	return true, 0
}

// Len returns the number of tracked keys.
func (l *WindowLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func (l *WindowLimiter) evictLocked(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for k, e := range l.entries {
		if now.Sub(e.last) >= e.win.refill() {
			delete(l.entries, k)
			continue
		}
		if oldestKey == "" || e.last.Before(oldest) {
			oldestKey, oldest = k, e.last
		}
	}
	if len(l.entries) >= l.maxKeys && oldestKey != "" {
		delete(l.entries, oldestKey)
	}
}
