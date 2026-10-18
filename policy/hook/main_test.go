package hook

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The repo does not depend on go.uber.org/goleak, so this is the same check
// done by hand: after the tests, no goroutine may still run code from this
// package. Goroutines owned by net/http (idle connections) do not count.
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		if leaked := waitNoLeak(3 * time.Second); leaked != "" {
			fmt.Fprintf(os.Stderr, "goroutine leak in policy/hook:\n%s\n", leaked)
			code = 1
		}
	}
	os.Exit(code)
}

// leakedGoroutines returns the stacks of goroutines that run a function of
// this package, other than tests and the leak check itself.
func leakedGoroutines() string {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var out []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if !strings.Contains(g, "theauth-go/v2/policy/hook.") {
			continue
		}
		if strings.Contains(g, "hook.leakedGoroutines") || strings.Contains(g, "hook.TestMain") ||
			strings.Contains(g, "testing.tRunner") || strings.Contains(g, "testing.(*T).Run") {
			continue
		}
		out = append(out, g)
	}
	return strings.Join(out, "\n\n")
}

func waitNoLeak(d time.Duration) string {
	deadline := time.Now().Add(d)
	for {
		leaked := leakedGoroutines()
		if leaked == "" || time.Now().After(deadline) {
			return leaked
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// requireNoLeak fails t if a goroutine of this package outlives the wait.
func requireNoLeak(t *testing.T) {
	t.Helper()
	if leaked := waitNoLeak(2 * time.Second); leaked != "" {
		t.Fatalf("goroutine leak:\n%s", leaked)
	}
}
