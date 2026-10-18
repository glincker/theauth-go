package otp

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

// TestVerifyParallelSingleWinner presents one correct code from many goroutines at once. A code is
// single use, so exactly one Verify may succeed. MaxAttempts is raised above the worker count so the
// attempt counter cannot hide a double spend.
func TestVerifyParallelSingleWinner(t *testing.T) {
	const workers = 32
	s, cp, _ := setup(t, func(c *Config) { c.MaxAttempts = workers * 4 })
	ctx := context.Background()
	if err := s.Issue(ctx, "login", "race@example.com"); err != nil {
		t.Fatal(err)
	}
	code := cp.last().Code

	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := s.Verify(ctx, "login", "race@example.com", code); err == nil {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("DOUBLE SPEND: %d Verify calls accepted one code, want 1", wins.Load())
	}
	if err := s.Verify(ctx, "login", "race@example.com", code); err == nil {
		t.Fatal("code accepted again after the race")
	}
}
