package hook

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func verdictHook(v Verdict) Hook {
	return Func(func(context.Context, Input) (Verdict, error) { return v, nil })
}

// blockUntilDone is a well behaved slow hook: it returns when ctx ends.
var blockUntilDone = Func(func(ctx context.Context, _ Input) (Verdict, error) {
	<-ctx.Done()
	return Verdict{}, ctx.Err()
})

func TestRunnerOutcomes(t *testing.T) {
	tests := []struct {
		name       string
		runner     *Runner
		ctx        func() (context.Context, context.CancelFunc)
		wantDec    Decision
		wantCode   Code
		wantReason string
		wantRule   string
	}{
		{name: "nil runner allows", runner: nil, wantDec: Allow},
		{name: "allow", runner: &Runner{Hook: verdictHook(Verdict{Decision: Allow, Reason: "fine"})}, wantDec: Allow},
		{
			name:    "deny with vendor code",
			runner:  &Runner{Hook: verdictHook(Verdict{Decision: Deny, Reason: "blocked by rule 7", Code: "R7", Guard: "g"})},
			wantDec: Deny, wantCode: CodeHookDenied, wantReason: "blocked by rule 7", wantRule: "R7",
		},
		{
			name:    "deny default reason",
			runner:  &Runner{Hook: verdictHook(Verdict{Decision: Deny})},
			wantDec: Deny, wantCode: CodeHookDenied, wantReason: defaultDenyReason,
		},
		{
			name:    "rule id wins over code",
			runner:  &Runner{Hook: verdictHook(Verdict{Decision: Deny, Reason: "x", Code: "R7", RuleID: "rule-1"})},
			wantDec: Deny, wantCode: CodeHookDenied, wantReason: "x", wantRule: "rule-1",
		},
		{
			name:    "escalate",
			runner:  &Runner{Hook: verdictHook(Verdict{Decision: Escalate})},
			wantDec: Escalate, wantCode: CodeApprovalRequired, wantReason: defaultEscalateReason,
		},
		{
			name:    "malformed verdict fails closed",
			runner:  &Runner{Hook: verdictHook(Verdict{Decision: "maybe"})},
			wantDec: Deny, wantCode: CodeHookError, wantReason: "beforeAuthorize hook failed",
		},
		{
			name:    "zero verdict fails closed",
			runner:  &Runner{Hook: verdictHook(Verdict{})},
			wantDec: Deny, wantCode: CodeHookError,
		},
		{
			name: "error fails closed",
			runner: &Runner{Hook: Func(func(context.Context, Input) (Verdict, error) {
				return Verdict{Decision: Allow}, errors.New("vendor down")
			})},
			wantDec: Deny, wantCode: CodeHookError,
		},
		{
			name: "panic fails closed",
			runner: &Runner{Hook: Func(func(context.Context, Input) (Verdict, error) {
				panic("boom")
			})},
			wantDec: Deny, wantCode: CodeHookError,
		},
		{
			name:    "timeout fails closed",
			runner:  &Runner{Hook: blockUntilDone, Timeout: 20 * time.Millisecond},
			wantDec: Deny, wantCode: CodeHookTimeout, wantReason: "beforeAuthorize hook timed out after 20ms",
		},
		{
			name:    "nil hook fails closed",
			runner:  &Runner{},
			wantDec: Deny, wantCode: CodeHookError,
		},
		{
			name:   "cancelled caller fails closed",
			runner: &Runner{Hook: verdictHook(Verdict{Decision: Allow})},
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			wantDec: Deny, wantCode: CodeHookError,
		},
		{
			name:   "caller deadline is a timeout",
			runner: &Runner{Hook: blockUntilDone, Timeout: time.Second},
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 20*time.Millisecond)
			},
			wantDec: Deny, wantCode: CodeHookTimeout,
		},
		{
			name:   "cancel during the call fails closed",
			runner: &Runner{Hook: blockUntilDone, Timeout: time.Second},
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(20*time.Millisecond, cancel)
				return ctx, cancel
			},
			wantDec: Deny, wantCode: CodeHookError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.Background(), context.CancelFunc(func() {})
			if tc.ctx != nil {
				ctx, cancel = tc.ctx()
			}
			defer cancel()
			out := tc.runner.Run(ctx, Input{AgentID: "a1", Action: "read", Resource: "r"})
			if out.Decision != tc.wantDec || out.Code != tc.wantCode {
				t.Fatalf("got %s/%s, want %s/%s (cause %v)", out.Decision, out.Code, tc.wantDec, tc.wantCode, out.Cause)
			}
			if tc.wantReason != "" && out.Reason != tc.wantReason {
				t.Fatalf("reason %q, want %q", out.Reason, tc.wantReason)
			}
			if out.RuleID != tc.wantRule {
				t.Fatalf("rule %q, want %q", out.RuleID, tc.wantRule)
			}
			err := out.Err()
			if out.Allowed() != (err == nil) {
				t.Fatalf("Allowed %v but Err %v", out.Allowed(), err)
			}
			if err != nil {
				var be *BlockedError
				if !errors.Is(err, ErrBlocked) || !errors.As(err, &be) || be.Code != tc.wantCode {
					t.Fatalf("error %v does not carry the code", err)
				}
			}
			requireNoLeak(t)
		})
	}
}

// A hook that ignores ctx keeps its goroutine only until it returns: the
// runner answers at the timeout and the late result is dropped.
func TestRunnerIgnoresLateResult(t *testing.T) {
	release := make(chan struct{})
	r := &Runner{Timeout: 20 * time.Millisecond, Hook: Func(func(context.Context, Input) (Verdict, error) {
		<-release
		return Verdict{Decision: Allow}, nil
	})}
	start := time.Now()
	out := r.Run(context.Background(), Input{AgentID: "a1"})
	if out.Code != CodeHookTimeout {
		t.Fatalf("got %s, want hook_timeout", out.Code)
	}
	if time.Since(start) > time.Second {
		t.Fatal("runner did not stop waiting at the timeout")
	}
	close(release)
	requireNoLeak(t)
}

func TestRunnerOnError(t *testing.T) {
	var kinds []ErrorKind
	var mu sync.Mutex
	record := func(info ErrorInfo) {
		mu.Lock()
		defer mu.Unlock()
		kinds = append(kinds, info.Kind)
		if info.AgentID != "a1" {
			t.Errorf("agent id %q", info.AgentID)
		}
	}
	hooks := []Hook{
		Func(func(context.Context, Input) (Verdict, error) { return Verdict{}, errors.New("x") }),
		Func(func(context.Context, Input) (Verdict, error) { panic("x") }),
		verdictHook(Verdict{Decision: "bogus"}),
		blockUntilDone,
	}
	for _, h := range hooks {
		(&Runner{Hook: h, Timeout: 10 * time.Millisecond, OnError: record}).Run(context.Background(), Input{AgentID: "a1"})
	}
	want := []ErrorKind{KindError, KindPanic, KindMalformed, KindTimeout}
	if strings.Join(kindStrings(kinds), ",") != strings.Join(kindStrings(want), ",") {
		t.Fatalf("kinds %v, want %v", kinds, want)
	}
	// A panicking OnError must not change the outcome.
	out := (&Runner{Hook: verdictHook(Verdict{}), OnError: func(ErrorInfo) { panic("x") }}).Run(context.Background(), Input{})
	if out.Code != CodeHookError {
		t.Fatalf("got %s", out.Code)
	}
}

func kindStrings(ks []ErrorKind) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = string(k)
	}
	return out
}

func TestResolvedTimeout(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == TimeoutEnv {
				return v
			}
			return ""
		}
	}
	tests := []struct {
		name string
		r    Runner
		want time.Duration
	}{
		{"default", Runner{Getenv: env("")}, DefaultTimeout},
		{"explicit", Runner{Timeout: 1500 * time.Millisecond, Getenv: env("100")}, 1500 * time.Millisecond},
		{"explicit clamped", Runner{Timeout: 5 * time.Minute}, MaxTimeout},
		{"env", Runner{Getenv: env("750")}, 750 * time.Millisecond},
		{"env max", Runner{Getenv: env("60000")}, MaxTimeout},
		{"env zero ignored", Runner{Getenv: env("0")}, DefaultTimeout},
		{"env too large ignored", Runner{Getenv: env("60001")}, DefaultTimeout},
		{"env negative ignored", Runner{Getenv: env("-5")}, DefaultTimeout},
		{"env garbage ignored", Runner{Getenv: env("2s")}, DefaultTimeout},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.ResolvedTimeout(); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCompose(t *testing.T) {
	var calls atomic.Int32
	counted := func(v Verdict) Hook {
		return Func(func(context.Context, Input) (Verdict, error) {
			calls.Add(1)
			return v, nil
		})
	}
	failing := Func(func(context.Context, Input) (Verdict, error) {
		calls.Add(1)
		return Verdict{}, errors.New("down")
	})
	allow := Verdict{Decision: Allow}
	tests := []struct {
		name      string
		hooks     []Hook
		want      Decision
		wantErr   bool
		wantCalls int32
		wantWhy   string
	}{
		{name: "empty allows", want: Allow},
		{name: "all allow", hooks: []Hook{counted(allow), counted(allow)}, want: Allow, wantCalls: 2},
		{
			name:  "deny overrides and stops",
			hooks: []Hook{counted(allow), counted(Verdict{Decision: Deny, Reason: "first"}), counted(Verdict{Decision: Deny, Reason: "second"})},
			want:  Deny, wantCalls: 2, wantWhy: "first",
		},
		{
			name:  "escalate beats allow",
			hooks: []Hook{counted(Verdict{Decision: Escalate, Reason: "e1"}), counted(allow), counted(Verdict{Decision: Escalate, Reason: "e2"})},
			want:  Escalate, wantCalls: 3, wantWhy: "e1",
		},
		{
			name:  "deny after escalate wins",
			hooks: []Hook{counted(Verdict{Decision: Escalate}), counted(Verdict{Decision: Deny, Reason: "no"})},
			want:  Deny, wantCalls: 2, wantWhy: "no",
		},
		{name: "error stops the run", hooks: []Hook{failing, counted(allow)}, wantErr: true, wantCalls: 1},
		{name: "malformed stops the run", hooks: []Hook{counted(Verdict{}), counted(allow)}, wantErr: true, wantCalls: 1},
		{name: "nil hooks skipped", hooks: []Hook{nil, counted(allow)}, want: Allow, wantCalls: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls.Store(0)
			v, err := Compose(tc.hooks...).BeforeAuthorize(context.Background(), Input{})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && v.Decision != tc.want {
				t.Fatalf("decision %s, want %s", v.Decision, tc.want)
			}
			if tc.wantWhy != "" && v.Reason != tc.wantWhy {
				t.Fatalf("reason %q, want %q", v.Reason, tc.wantWhy)
			}
			if calls.Load() != tc.wantCalls {
				t.Fatalf("calls %d, want %d", calls.Load(), tc.wantCalls)
			}
		})
	}
}

func TestComposeUnderRunnerFailsClosed(t *testing.T) {
	r := &Runner{Hook: Compose(verdictHook(Verdict{Decision: Allow}), Func(func(context.Context, Input) (Verdict, error) {
		panic("second hook")
	}))}
	if out := r.Run(context.Background(), Input{}); out.Code != CodeHookError {
		t.Fatalf("got %s, want hook_error", out.Code)
	}
}

func TestOutcomeSanitizesVerdict(t *testing.T) {
	md := map[string]any{"nested": map[string]any{"x": 1}, "n": 2, "ok": true, "long": strings.Repeat("é", 200)}
	for i := 0; i < 20; i++ {
		md["k"+string(rune('a'+i))] = "v"
	}
	r := &Runner{Hook: verdictHook(Verdict{Decision: Deny, Reason: "x", Guard: strings.Repeat("g", 300), Metadata: md})}
	out := r.Run(context.Background(), Input{})
	if len(out.Guard) != maxClip {
		t.Fatalf("guard length %d", len(out.Guard))
	}
	if len(out.Metadata) != maxMetadataKeys {
		t.Fatalf("metadata keys %d", len(out.Metadata))
	}
	if _, ok := out.Metadata["nested"]; ok {
		t.Fatal("non scalar metadata kept")
	}
	if s, ok := out.Metadata["long"].(string); ok && (len(s) > maxClip || !strings.HasPrefix(strings.Repeat("é", 200), s)) {
		t.Fatalf("clip broke a rune: %q", s)
	}
	rec := out.AuditRecord()
	if rec["decision"] != "deny" || rec["code"] != "hook_denied" {
		t.Fatalf("audit record %v", rec)
	}
}
