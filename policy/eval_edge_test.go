package policy

import (
	"testing"
	"time"
)

// TestTimeWindowBoundaries pins the inclusive-start and exclusive-end rules
// of absolute and daily windows, including wrap-around and degenerate ranges.
func TestTimeWindowBoundaries(t *testing.T) {
	utc := func(h, m int) time.Time { return time.Date(2026, 10, 16, h, m, 0, 0, time.UTC) }
	tests := []struct {
		name string
		fn   func(time.Time) bool
		now  time.Time
		want bool
	}{
		{"absolute start inclusive", func(n time.Time) bool {
			return inAbsoluteWindow([]string{"2026-10-16T12:00:00Z", ""}, n)
		}, utc(12, 0), true},
		{"absolute before start", func(n time.Time) bool {
			return inAbsoluteWindow([]string{"2026-10-16T12:00:00Z", ""}, n)
		}, utc(11, 59), false},
		{"absolute end exclusive", func(n time.Time) bool {
			return inAbsoluteWindow([]string{"", "2026-10-16T12:00:00Z"}, n)
		}, utc(12, 0), false},
		{"absolute open both ends", func(n time.Time) bool {
			return inAbsoluteWindow([]string{"", ""}, n)
		}, utc(3, 0), true},
		{"absolute malformed bound fails closed", func(n time.Time) bool {
			return inAbsoluteWindow([]string{"yesterday", ""}, n)
		}, utc(3, 0), false},
		{"absolute wrong arity fails closed", func(n time.Time) bool {
			return inAbsoluteWindow([]string{""}, n)
		}, utc(3, 0), false},
		{"daily start inclusive", func(n time.Time) bool {
			return inDailyWindow([]string{"09:00", "17:00"}, n)
		}, utc(9, 0), true},
		{"daily end exclusive", func(n time.Time) bool {
			return inDailyWindow([]string{"09:00", "17:00"}, n)
		}, utc(17, 0), false},
		{"daily wrap-around late", func(n time.Time) bool {
			return inDailyWindow([]string{"22:00", "06:00"}, n)
		}, utc(23, 30), true},
		{"daily wrap-around early", func(n time.Time) bool {
			return inDailyWindow([]string{"22:00", "06:00"}, n)
		}, utc(5, 59), true},
		{"daily wrap-around outside", func(n time.Time) bool {
			return inDailyWindow([]string{"22:00", "06:00"}, n)
		}, utc(12, 0), false},
		{"daily equal bounds never match", func(n time.Time) bool {
			return inDailyWindow([]string{"09:00", "09:00"}, n)
		}, utc(9, 0), false},
		{"daily is evaluated in UTC, not the instant's zone", func(n time.Time) bool {
			loc := time.FixedZone("UTC+5", 5*3600)
			return inDailyWindow([]string{"09:00", "17:00"}, n.In(loc))
		}, utc(4, 30), false},
		{"daily bad clock fails closed", func(n time.Time) bool {
			return inDailyWindow([]string{"25:00", "17:00"}, n)
		}, utc(12, 0), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fn(tt.now); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMatchEdgeCases covers glob behaviour the statement matcher relies on:
// trailing and repeated stars, escaped stars, and empty inputs.
func TestMatchEdgeCases(t *testing.T) {
	tests := []struct {
		name, pattern, s string
		want             bool
	}{
		{"empty pattern empty input", "", "", true},
		{"empty pattern non-empty input", "", "x", false},
		{"star matches empty", "a*", "a", true},
		{"star crosses slash", "a*c", "a/b/c", true},
		{"repeated stars", "**a**", "xa", true},
		{"escaped star is literal", `a\*`, "a*", true},
		{"escaped star does not wildcard", `a\*`, "abc", false},
		{"trailing backslash is literal", `a\`, `a\`, true},
		{"case sensitive", "Deploy", "deploy", false},
		{"star then literal backtrack", "*ab", "aab", true},
		{"no backtrack needed to fail", "a*b", "acbd", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Match(tt.pattern, tt.s); got != tt.want {
				t.Fatalf("Match(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
			}
		})
	}
}

// TestEvaluateStatementIDs checks that unnamed statements report their index
// after the lazy-id change, for allow, deny and escalate outcomes.
func TestEvaluateStatementIDs(t *testing.T) {
	tests := []struct {
		name   string
		doc    string
		effect Effect
		stmt   string
	}{
		{"allow unnamed index", `{"version":"1","statements":[{"effect":"allow","actions":["x"],"resources":["*"]}]}`, Allow, "stmt-0"},
		{"allow second index", `{"version":"1","statements":[{"effect":"deny","actions":["y"],"resources":["*"]},{"effect":"allow","actions":["x"],"resources":["*"]}]}`, Allow, "stmt-1"},
		{"deny unnamed index", `{"version":"1","statements":[{"effect":"deny","actions":["x"],"resources":["*"]}]}`, Deny, "stmt-0"},
		{"escalate unnamed index", `{"version":"1","statements":[{"effect":"escalate","actions":["x"],"resources":["*"]}]}`, Escalate, "stmt-0"},
		{"named keeps name", `{"version":"1","statements":[{"id":"s","effect":"allow","actions":["x"],"resources":["*"]}]}`, Allow, "s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustParse(t, tt.doc)
			d := Evaluator{}.Evaluate(Request{Action: "x", Resource: "r"}, p)
			if d.Effect != tt.effect || d.StatementID != tt.stmt {
				t.Fatalf("got effect=%q stmt=%q, want effect=%q stmt=%q", d.Effect, d.StatementID, tt.effect, tt.stmt)
			}
		})
	}
}
