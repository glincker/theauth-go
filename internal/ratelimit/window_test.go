package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestWindowLimiterBoundedAndRecovers(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	l := NewWindowLimiter(Window{Requests: 1, Per: time.Second}, 4, clock)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("first must pass")
	}
	ok, retry := l.Allow("a")
	if ok || retry <= 0 || retry > time.Second {
		t.Fatalf("second must be refused with retry, got %v %v", ok, retry)
	}
	mu.Lock()
	now = now.Add(retry)
	mu.Unlock()
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("must recover after retry")
	}
	for i := 0; i < 50; i++ {
		l.Allow(fmt.Sprintf("k%d", i))
	}
	if l.Len() > 4 {
		t.Fatalf("unbounded: %d", l.Len())
	}
	if ok, _ := NewWindowLimiter(Window{}, 0, nil).Allow("x"); !ok {
		t.Fatal("disabled window allows all")
	}
}

func TestWindowLimiterPerKeyParamsReplaceBucket(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewWindowLimiter(Window{Requests: 1, Per: time.Minute}, 0, func() time.Time { return now })
	small, big := Window{Requests: 1, Per: time.Minute}, Window{Requests: 4, Per: time.Minute}
	if ok, _ := l.AllowWith("a", small); !ok {
		t.Fatal("first")
	}
	if ok, _ := l.AllowWith("a", small); ok {
		t.Fatal("small budget spent")
	}
	for i := 0; i < 4; i++ {
		if ok, _ := l.AllowWith("a", big); !ok {
			t.Fatalf("raised limit applies on next request (%d)", i)
		}
	}
	if ok, _ := l.AllowCurrent("a"); ok {
		t.Fatal("AllowCurrent keeps the key's current (spent) bucket")
	}
	if ok, _ := l.AllowCurrent("fresh"); !ok {
		t.Fatal("unseen key starts on the default budget")
	}
}
