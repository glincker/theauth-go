package chain

import (
	"reflect"
	"testing"
	"time"
)

func TestDepth(t *testing.T) {
	cases := []struct {
		name string
		act  *Actor
		want int
	}{
		{"nil chain is depth 1", nil, 1},
		{"single agent is depth 2", &Actor{Sub: "agent:A"}, 2},
		{"two agents is depth 3", &Actor{Sub: "agent:B", Act: &Actor{Sub: "agent:A"}}, 3},
		{"three agents is depth 4", &Actor{Sub: "agent:C", Act: &Actor{Sub: "agent:B", Act: &Actor{Sub: "agent:A"}}}, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Depth(c.act); got != c.want {
				t.Fatalf("Depth(%v) = %d, want %d", c.act, got, c.want)
			}
		})
	}
}

func TestPrependPreservesExistingChain(t *testing.T) {
	prior := &Actor{Sub: "agent:A"}
	out := Prepend("agent:B", prior)
	if out.Sub != "agent:B" {
		t.Fatalf("inner sub: want agent:B, got %q", out.Sub)
	}
	if out.Act == nil || out.Act.Sub != "agent:A" {
		t.Fatalf("inner act: want agent:A, got %+v", out.Act)
	}
	// The original chain is not mutated.
	if prior.Act != nil {
		t.Fatalf("prepend mutated input chain")
	}
}

func TestPrependOnNilStartsFreshChain(t *testing.T) {
	out := Prepend("agent:A", nil)
	if out.Sub != "agent:A" || out.Act != nil {
		t.Fatalf("Prepend(A, nil) = %+v, want {agent:A, nil}", out)
	}
}

func TestWalkVisitsInnermostFirst(t *testing.T) {
	chain := &Actor{Sub: "agent:C", Act: &Actor{Sub: "agent:B", Act: &Actor{Sub: "agent:A"}}}
	var seen []string
	Walk(chain, func(a *Actor) bool { seen = append(seen, a.Sub); return true })
	want := []string{"agent:C", "agent:B", "agent:A"}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("walk order: want %v, got %v", want, seen)
	}
}

func TestWalkStopsOnFalse(t *testing.T) {
	chain := &Actor{Sub: "agent:C", Act: &Actor{Sub: "agent:B"}}
	count := 0
	Walk(chain, func(a *Actor) bool { count++; return false })
	if count != 1 {
		t.Fatalf("walk stop: want 1 visit, got %d", count)
	}
}

func TestScopeSubsetStrict(t *testing.T) {
	cases := []struct {
		name string
		sub  []string
		sup  []string
		want bool
	}{
		{"empty is subset of anything", nil, []string{"a", "b"}, true},
		{"equal is subset", []string{"a", "b"}, []string{"a", "b"}, true},
		{"strict subset ok", []string{"a"}, []string{"a", "b"}, true},
		{"extra scope rejects", []string{"a", "c"}, []string{"a", "b"}, false},
		{"superset rejects", []string{"a", "b", "c"}, []string{"a", "b"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ScopeSubset(c.sub, c.sup); got != c.want {
				t.Fatalf("ScopeSubset(%v,%v) = %v, want %v", c.sub, c.sup, got, c.want)
			}
		})
	}
}

func TestScopeIntersectPreservesOrder(t *testing.T) {
	got := ScopeIntersect([]string{"a", "b", "c"}, []string{"c", "a"})
	want := []string{"a", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("intersect: want %v, got %v", want, got)
	}
}

func TestTightenDurationPicksStrictMin(t *testing.T) {
	now := time.Now()
	a := now.Add(30 * time.Minute)
	b := now.Add(10 * time.Minute)
	c := now.Add(20 * time.Minute)
	got := TightenDuration(a, b, c)
	if !got.Equal(b) {
		t.Fatalf("tighten: want %v (b), got %v", b, got)
	}
}

func TestTightenDurationIgnoresZero(t *testing.T) {
	now := time.Now()
	a := now.Add(30 * time.Minute)
	got := TightenDuration(time.Time{}, a, time.Time{})
	if !got.Equal(a) {
		t.Fatalf("tighten ignore zero: want %v, got %v", a, got)
	}
}

func TestTightenDurationAllZeroReturnsZero(t *testing.T) {
	if got := TightenDuration(time.Time{}, time.Time{}); !got.IsZero() {
		t.Fatalf("all-zero tighten: want zero, got %v", got)
	}
}
