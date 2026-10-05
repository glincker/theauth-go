package policy

import (
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		pat, s string
		want   bool
	}{
		{"*", "", true},
		{"*", "anything/at/all", true},
		{"", "", true},
		{"", "x", false},
		{"a", "a", true},
		{"a", "A", false},
		{"deploy:*", "deploy:create", true},
		{"deploy:*", "deploy", false},
		{"*:read", "project:read", true},
		{"*:read", "project:readonly", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "acb", false},
		{"**", "x", true},
		{"a**b", "ab", true},
		{"project/*/env/*", "project/p1/env/prod", true},
		{"project/*", "project/p1/env/prod", true},
		{"project/p1", "project/p10", false},
		{`a\*b`, "a*b", true},
		{`a\*b`, "aXb", false},
		{`a\\b`, `a\b`, true},
		{`trail\`, `trail\`, true},
		{"*abc", "xxabcabc", true},
		{"*abc", "xxabcab", false},
		{"é*", "éa", true},
	}
	for _, tc := range tests {
		if got := Match(tc.pat, tc.s); got != tc.want {
			t.Errorf("Match(%q,%q)=%v want %v", tc.pat, tc.s, got, tc.want)
		}
	}
}

func TestMatchPathological(t *testing.T) {
	pat := strings.Repeat("a*", 200) + "b"
	if Match(pat, strings.Repeat("a", 5000)) {
		t.Fatal("unexpected match")
	}
}

func TestEscapeRoundTrip(t *testing.T) {
	for _, v := range []string{"plain", "*", `a\b`, `**\*`, ""} {
		if !Match(Escape(v), v) {
			t.Errorf("Escape(%q) does not match itself", v)
		}
		if v != "" && Match(Escape(v), v+"x") {
			t.Errorf("Escape(%q) matched longer string", v)
		}
	}
}

func FuzzMatch(f *testing.F) {
	for _, s := range []string{"*", "a*b", `\*`, "", "a**b*c"} {
		f.Add(s, "aXbYc")
	}
	f.Fuzz(func(t *testing.T, pat, s string) {
		_ = Match(pat, s)
		if !Match(Escape(s), s) {
			t.Fatalf("Escape(%q) must match itself", s)
		}
		if !Match("*", s) {
			t.Fatal("* must match everything")
		}
	})
}
