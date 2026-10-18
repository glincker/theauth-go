package hook

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Timeout settings. The env var name and the bounds match the TypeScript
// library's hookSafety.
const (
	// DefaultTimeout applies when Runner.Timeout is zero and the env var is
	// unset or invalid.
	DefaultTimeout = 2 * time.Second
	// MaxTimeout caps any configured timeout.
	MaxTimeout = 60 * time.Second
	// TimeoutEnv overrides DefaultTimeout, in whole milliseconds (1 to 60000).
	// An explicit Runner.Timeout wins over it.
	TimeoutEnv = "THEAUTH_HOOK_TIMEOUT_MS"
)

// ErrBlocked is matched (errors.Is) by every *BlockedError.
var ErrBlocked = errors.New("hook: call blocked")

var errTimedOut = errors.New("hook: timed out")

// Runner runs one Hook under the safety rules: a timeout, panic recovery and
// fail closed. A nil *Runner means no hook is configured and Run allows. Build
// several hooks into one with Compose. The zero Timeout uses TimeoutEnv, then
// DefaultTimeout. A Runner is safe for concurrent use once configured.
type Runner struct {
	// Hook decides. A Runner with a nil Hook denies every call with
	// hook_error, so a half configured runner never opens access.
	Hook Hook
	// Timeout bounds one run. Zero means TimeoutEnv or DefaultTimeout. Values
	// above MaxTimeout are clamped.
	Timeout time.Duration
	// Getenv reads TimeoutEnv. Nil uses os.Getenv.
	Getenv func(string) string
	// OnError, when set, sees every timeout, error, panic and malformed
	// verdict. It cannot change the outcome; a panic in it is swallowed.
	OnError func(ErrorInfo)
}

// ErrorKind classifies a failed run.
type ErrorKind string

// Failure kinds reported to Runner.OnError.
const (
	KindTimeout   ErrorKind = "timeout"
	KindError     ErrorKind = "error"
	KindPanic     ErrorKind = "panic"
	KindMalformed ErrorKind = "malformed"
)

// ErrorInfo describes one failed run.
type ErrorInfo struct {
	Kind    ErrorKind
	Err     error
	Elapsed time.Duration
	AgentID string
}

// Outcome is the result of one run.
type Outcome struct {
	// Decision is Allow, Deny or Escalate. Every failure is Deny.
	Decision Decision
	// Code is empty for Allow, approval_required for Escalate, and
	// hook_denied, hook_timeout or hook_error for Deny.
	Code Code
	// Reason is safe to return to the calling agent. For a failure it is a
	// fixed text; the cause is in Cause, for logs only.
	Reason   string
	Guard    string
	RuleID   string
	Metadata map[string]any
	Elapsed  time.Duration
	// Cause is the error behind a hook_timeout or hook_error outcome. It names
	// a guard by origin only and never holds secrets, but it may hold network
	// detail, so keep it out of responses.
	Cause error
}

// Allowed reports whether the hook let the call continue to normal policy.
func (o Outcome) Allowed() bool { return o.Decision == Allow }

// Err returns nil when allowed, otherwise a *BlockedError.
func (o Outcome) Err() error {
	if o.Allowed() {
		return nil
	}
	return &BlockedError{
		Decision: o.Decision, Code: o.Code, Reason: o.Reason,
		Guard: o.Guard, RuleID: o.RuleID, Metadata: o.Metadata, cause: o.Cause,
	}
}

// AuditRecord returns the fields to store on an audit row under the key
// "hook": decision, code, guard, rule_id, metadata and elapsed_ms.
func (o Outcome) AuditRecord() map[string]any {
	rec := map[string]any{
		"decision":   string(o.Decision),
		"elapsed_ms": o.Elapsed.Milliseconds(),
	}
	if o.Code != "" {
		rec["code"] = string(o.Code)
	}
	if o.Guard != "" {
		rec["guard"] = o.Guard
	}
	if o.RuleID != "" {
		rec["rule_id"] = o.RuleID
	}
	if len(o.Metadata) > 0 {
		rec["metadata"] = o.Metadata
	}
	return rec
}

// BlockedError is returned for a call a hook denied or escalated, or that
// failed closed. errors.Is(err, ErrBlocked) matches it.
type BlockedError struct {
	Decision Decision
	Code     Code
	Reason   string
	Guard    string
	RuleID   string
	Metadata map[string]any
	cause    error
}

// Error implements error. It holds the safe Reason, never the cause.
func (e *BlockedError) Error() string {
	if e.Decision == Escalate {
		return fmt.Sprintf("hook: approval required (%s): %s", e.Code, e.Reason)
	}
	return fmt.Sprintf("hook: call denied (%s): %s", e.Code, e.Reason)
}

// Is makes errors.Is(err, ErrBlocked) true.
func (e *BlockedError) Is(target error) bool { return target == ErrBlocked }

// Unwrap returns the failure cause of a hook_timeout or hook_error outcome.
func (e *BlockedError) Unwrap() error { return e.cause }

// ResolvedTimeout returns the timeout Run applies.
func (r *Runner) ResolvedTimeout() time.Duration {
	if r.Timeout > 0 {
		return min(r.Timeout, MaxTimeout)
	}
	getenv := r.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if raw := strings.TrimSpace(getenv(TimeoutEnv)); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 && ms <= int(MaxTimeout/time.Millisecond) {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return DefaultTimeout
}

type result struct {
	v   Verdict
	err error
	pan bool
}

// Run asks the hook about one call. It never panics and always returns within
// the timeout plus scheduling slack. A cancelled ctx denies with hook_error,
// an expired deadline (the runner's or the caller's) with hook_timeout.
func (r *Runner) Run(ctx context.Context, in Input) Outcome {
	if r == nil {
		return Outcome{Decision: Allow}
	}
	start := time.Now()
	if r.Hook == nil {
		return r.fail(in, KindError, errors.New("hook: runner has no hook"), start, 0)
	}
	timeout := r.ResolvedTimeout()
	if err := ctx.Err(); err != nil {
		return r.fail(in, ctxKind(ctx, err), err, start, timeout)
	}
	hctx, cancel := context.WithTimeoutCause(ctx, timeout, errTimedOut)
	defer cancel()

	ch := make(chan result, 1) // buffered: a late hook never blocks on send
	go func() {
		var res result
		defer func() {
			if p := recover(); p != nil {
				res = result{err: fmt.Errorf("hook: panic: %v", p), pan: true}
			}
			ch <- res
		}()
		v, err := r.Hook.BeforeAuthorize(hctx, in)
		res = result{v: v, err: err}
	}()

	select {
	case res := <-ch:
		switch {
		case res.pan:
			return r.fail(in, KindPanic, res.err, start, timeout)
		case res.err != nil:
			if hctx.Err() != nil {
				return r.fail(in, ctxKind(hctx, res.err), res.err, start, timeout)
			}
			return r.fail(in, KindError, res.err, start, timeout)
		}
		return r.verdict(in, res.v, start, timeout)
	case <-hctx.Done():
		return r.fail(in, ctxKind(hctx, hctx.Err()), context.Cause(hctx), start, timeout)
	}
}

// ctxKind maps a done context to timeout (deadline) or error (cancelled).
func ctxKind(ctx context.Context, err error) ErrorKind {
	cause := context.Cause(ctx)
	if errors.Is(cause, errTimedOut) || errors.Is(cause, context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return KindTimeout
	}
	return KindError
}

func (r *Runner) verdict(in Input, v Verdict, start time.Time, timeout time.Duration) Outcome {
	out := Outcome{
		Decision: v.Decision,
		Guard:    clip(v.Guard),
		RuleID:   clip(v.RuleID),
		Metadata: sanitizeMetadata(v.Metadata),
		Elapsed:  time.Since(start),
	}
	if out.RuleID == "" {
		out.RuleID = clip(v.Code)
	}
	switch v.Decision {
	case Allow:
		return Outcome{Decision: Allow, Elapsed: out.Elapsed}
	case Deny:
		out.Code, out.Reason = CodeHookDenied, orDefault(v.Reason, defaultDenyReason)
	case Escalate:
		out.Code, out.Reason = CodeApprovalRequired, orDefault(v.Reason, defaultEscalateReason)
	default:
		return r.fail(in, KindMalformed, ErrMalformedVerdict, start, timeout)
	}
	return out
}

func (r *Runner) fail(in Input, kind ErrorKind, cause error, start time.Time, timeout time.Duration) Outcome {
	elapsed := time.Since(start)
	r.notify(ErrorInfo{Kind: kind, Err: cause, Elapsed: elapsed, AgentID: in.AgentID})
	if kind == KindTimeout {
		if cause == nil || errors.Is(cause, errTimedOut) {
			cause = context.DeadlineExceeded
		}
		return Outcome{
			Decision: Deny, Code: CodeHookTimeout, Elapsed: elapsed, Cause: cause,
			Reason: fmt.Sprintf("beforeAuthorize hook timed out after %dms", timeout.Milliseconds()),
		}
	}
	return Outcome{Decision: Deny, Code: CodeHookError, Reason: "beforeAuthorize hook failed", Elapsed: elapsed, Cause: cause}
}

func (r *Runner) notify(info ErrorInfo) {
	if r.OnError == nil {
		return
	}
	defer func() { _ = recover() }()
	r.OnError(info)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// clip truncates s to maxClip bytes on a rune boundary.
func clip(s string) string {
	if len(s) <= maxClip {
		return s
	}
	cut := maxClip
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// sanitizeMetadata keeps scalar values only (string, bool, finite numbers),
// at most maxMetadataKeys keys, strings clipped. Keys are taken in sorted
// order so the kept set is deterministic.
func sanitizeMetadata(raw map[string]any) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make(map[string]any, min(len(raw), maxMetadataKeys))
	for _, k := range keys {
		if len(out) >= maxMetadataKeys {
			break
		}
		switch v := raw[k].(type) {
		case string:
			out[clip(k)] = clip(v)
		case bool:
			out[clip(k)] = v
		case float64:
			if !math.IsNaN(v) && !math.IsInf(v, 0) {
				out[clip(k)] = v
			}
		case int:
			out[clip(k)] = float64(v)
		case int64:
			out[clip(k)] = float64(v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
