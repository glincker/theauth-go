package chain

import (
	"testing"
	"time"
)

// TestDepthEdges covers the nil chain and nested actor depths.
func TestDepthEdges(t *testing.T) {
	tests := []struct {
		name string
		act  *Actor
		want int
	}{
		{"no act claim", nil, 1},
		{"one actor", &Actor{Sub: "agent:a"}, 2},
		{"two actors", &Actor{Sub: "agent:b", Act: &Actor{Sub: "agent:a"}}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Depth(tt.act); got != tt.want {
				t.Fatalf("Depth = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestWalkStopsEarly checks that Walk honours a false return and visits
// innermost first.
func TestWalkStopsEarly(t *testing.T) {
	chainAct := &Actor{Sub: "a", Act: &Actor{Sub: "b", Act: &Actor{Sub: "c"}}}
	var seen []string
	Walk(chainAct, func(a *Actor) bool {
		seen = append(seen, a.Sub)
		return a.Sub != "b"
	})
	if len(seen) != 2 || seen[0] != "a" || seen[1] != "b" {
		t.Fatalf("visited %v, want [a b]", seen)
	}
	Walk(nil, func(*Actor) bool {
		t.Fatal("Walk on nil chain must not call fn")
		return true
	})
}

// TestPrependDoesNotMutateInput checks that Prepend returns a fresh chain.
func TestPrependDoesNotMutateInput(t *testing.T) {
	existing := &Actor{Sub: "outer"}
	out := Prepend("inner", existing)
	if existing.Act != nil || existing.Sub != "outer" {
		t.Fatalf("input mutated: %+v", existing)
	}
	if out.Sub != "inner" || out.Act != existing {
		t.Fatalf("unexpected chain %+v", out)
	}
}

// TestScopeHelpersEdges covers empty and duplicate scope lists.
func TestScopeHelpersEdges(t *testing.T) {
	if !ScopeSubset(nil, []string{"a"}) {
		t.Fatal("empty subset must be a subset of anything")
	}
	if ScopeSubset([]string{"a"}, nil) {
		t.Fatal("non-empty subset of empty superset must fail")
	}
	got := ScopeIntersect([]string{"b", "a", "b"}, []string{"a", "b"})
	if len(got) != 3 || got[0] != "b" || got[1] != "a" || got[2] != "b" {
		t.Fatalf("ScopeIntersect = %v, want order-preserving [b a b]", got)
	}
	if out := ScopeIntersect([]string{"x"}, nil); out == nil || len(out) != 0 {
		t.Fatalf("ScopeIntersect with empty b = %#v, want empty non-nil", out)
	}
}

// TestTightenDurationEdges covers zero-only and mixed candidate sets.
func TestTightenDurationEdges(t *testing.T) {
	base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	if got := TightenDuration(); !got.IsZero() {
		t.Fatalf("no candidates = %v, want zero", got)
	}
	if got := TightenDuration(time.Time{}, time.Time{}); !got.IsZero() {
		t.Fatalf("all zero = %v, want zero", got)
	}
	got := TightenDuration(time.Time{}, base.Add(time.Hour), base.Add(time.Minute), time.Time{})
	if !got.Equal(base.Add(time.Minute)) {
		t.Fatalf("TightenDuration = %v, want strict minimum", got)
	}
}
