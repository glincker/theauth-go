package integration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/glincker/theauth-go/v2/integration/internal/testutil"
)

type captureHandler struct {
	mu   sync.Mutex
	recs []string
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *captureHandler) WithGroup(string) slog.Handler            { return h }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
		return true
	})
	h.mu.Lock()
	h.recs = append(h.recs, b.String())
	h.mu.Unlock()
	return nil
}

func TestLogsNeverContainEmailAddresses(t *testing.T) {
	h := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	a, _ := newTestAuth(t)
	ctx := context.Background()
	const known, unknown = "Privacy.Known@Example.com", "ghost.nobody@example.com"

	steps := []struct {
		name string
		run  func()
	}{
		{"signup", func() { _, _, _ = testutil.SignupWithPasswordForTest(a, ctx, known, validPassword) }},
		{"signin ok", func() { _, _, _ = testutil.SigninWithPasswordForTest(a, ctx, known, validPassword, "ua", "") }},
		{"signin bad password", func() { _, _, _ = testutil.SigninWithPasswordForTest(a, ctx, known, "wrong-password-xx", "ua", "") }},
		{"signin unknown user", func() { _, _, _ = testutil.SigninWithPasswordForTest(a, ctx, unknown, validPassword, "ua", "") }},
		{"magic link request", func() { _, _ = testutil.RequestMagicLinkForTest(a, ctx, known) }},
		{"reset request known", func() { _, _ = testutil.RequestPasswordResetForTest(a, ctx, known) }},
		{"reset request unknown", func() { _, _ = testutil.RequestPasswordResetForTest(a, ctx, unknown) }},
	}
	for _, s := range steps {
		s.run()
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.recs) == 0 {
		t.Fatal("expected captured log records")
	}
	for _, rec := range h.recs {
		low := strings.ToLower(rec)
		for _, needle := range []string{"privacy.known", "ghost.nobody", "@example.com"} {
			if strings.Contains(low, needle) {
				t.Errorf("log record leaks email (%q): %s", needle, rec)
			}
		}
	}
}
