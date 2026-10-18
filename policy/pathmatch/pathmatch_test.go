package pathmatch

import (
	"encoding/json"
	"os"
	"testing"
)

type vectors struct {
	Items []string `json:"items"`
	Colon []string `json:"colon"`
	Path  []string `json:"path"`
}

// TestVectorsMatchTS replays every pattern and resource pair of the generated corpus against the
// result of the TS matcher.
func TestVectorsMatchTS(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	n := len(v.Items)
	if n < 50 || len(v.Colon) != n || len(v.Path) != n {
		t.Fatalf("bad vector file: %d items, %d colon rows, %d path rows", n, len(v.Colon), len(v.Path))
	}
	for _, c := range []struct {
		name string
		rows []string
		fn   func(string, string) bool
	}{{"colon", v.Colon, MatchColon}, {"path", v.Path, MatchPath}} {
		t.Run(c.name, func(t *testing.T) {
			bad := 0
			for i, p := range v.Items {
				if len(c.rows[i]) != n {
					t.Fatalf("row %d has %d columns, want %d", i, len(c.rows[i]), n)
				}
				for j, r := range v.Items {
					want := c.rows[i][j] == '1'
					if got := c.fn(p, r); got != want {
						bad++
						if bad <= 10 {
							t.Errorf("%s(%q, %q) = %v, TS says %v", c.name, p, r, got, want)
						}
					}
				}
			}
		})
	}
}

func TestPathRules(t *testing.T) {
	tests := []struct {
		name, pattern, resource string
		want                    bool
	}{
		{"star is one segment", "ros2:/fleet/*/cmd", "ros2:/fleet/a/cmd", true},
		{"star is not two segments", "ros2:/fleet/*/cmd", "ros2:/fleet/a/b/cmd", false},
		{"double star is one or more", "ros2:/fleet/**", "ros2:/fleet/a/b/c", true},
		{"double star never empty", "ros2:/fleet/**/cmd", "ros2:/fleet//cmd", false},
		{"dot dot is not matched", "ros2:/fleet/**/x", "ros2:/fleet/a/../x", false},
		{"dot is not matched", "ros2:/fleet/*/x", "ros2:/fleet/./x", false},
		{"traversal cannot ride a glob", "ros2:/fleet/**/cmd", "ros2:/fleet/a/../../admin/cmd", false},
		{"case sensitive", "ros2:/fleet/*/cmd", "ros2:/Fleet/a/cmd", false},
		{"nothing is decoded", "ros2:/fleet/**/x", "ros2:/fleet/%2e%2e/x", true},
		{"partial glob is literal", "ros2:/fleet/r*", "ros2:/fleet/robot", false},
		{"colon never crossed", "ros2:/fleet/*", "ros2:/fleet/a:b", false},
		{"lone star", "*", "anything:at:all", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchPath(tc.pattern, tc.resource); got != tc.want {
				t.Fatalf("MatchPath(%q, %q) = %v, want %v", tc.pattern, tc.resource, got, tc.want)
			}
		})
	}
}

func TestColonStaysLiteral(t *testing.T) {
	if MatchColon("ros2:/fleet/*", "ros2:/fleet/a") {
		t.Fatal("colon mode must treat a path star as literal text")
	}
	if !Match(Colon, "a:*", "a:b:c") || !Match(Path, "a:*", "a:b:c") {
		t.Fatal("a trailing colon star matches the rest in both modes")
	}
	if Resolve("path") != Path || Resolve("PATH") != Colon || Resolve("") != Colon {
		t.Fatal("only the exact string path selects path mode")
	}
}
