package epoch

import "testing"

func TestCommitDroppedAfterInvalidate(t *testing.T) {
	var s Set
	tok := s.Token("k")
	removed := false
	s.Invalidate("k", func() { removed = true })
	if !removed {
		t.Fatal("remove not run")
	}
	if s.Commit("k", tok, func() { t.Fatal("stale store ran") }) {
		t.Fatal("stale commit reported success")
	}
	if !s.Commit("k", s.Token("k"), func() {}) {
		t.Fatal("fresh commit dropped")
	}
}

func TestInvalidateAllDropsEveryKey(t *testing.T) {
	var s Set
	keys := []string{"a", "b", "agent:1", "zzz"}
	toks := make([]uint64, len(keys))
	for i, k := range keys {
		toks[i] = s.Token(k)
	}
	s.InvalidateAll(nil)
	for i, k := range keys {
		if s.Commit(k, toks[i], func() {}) {
			t.Fatalf("stale commit for %q survived InvalidateAll", k)
		}
	}
}
