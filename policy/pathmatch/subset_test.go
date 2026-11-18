package pathmatch

import (
	"encoding/json"
	"os"
	"testing"
)

type subsetVectors struct {
	Items        []string `json:"items"`
	SubsetColon  []string `json:"subsetColon"`
	SubsetPath   []string `json:"subsetPath"`
	OverlapColon []string `json:"overlapColon"`
	OverlapPath  []string `json:"overlapPath"`
	Perms        []struct {
		Mode   string `json:"mode"`
		Parent []struct {
			Resource string   `json:"resource"`
			Actions  []string `json:"actions"`
		} `json:"parent"`
		Child []struct {
			Resource string   `json:"resource"`
			Actions  []string `json:"actions"`
		} `json:"child"`
		Want bool `json:"want"`
	} `json:"perms"`
}

// TestSubsetVectorsMatchTS replays the TS isResourceSubset, resourcesOverlap and
// isPermissionSubset results.
func TestSubsetVectorsMatchTS(t *testing.T) {
	raw, err := os.ReadFile("testdata/subset_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v subsetVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	n := len(v.Items)
	if n < 50 || len(v.SubsetColon) != n || len(v.SubsetPath) != n || len(v.OverlapColon) != n || len(v.OverlapPath) != n {
		t.Fatalf("bad vector file: %d items", n)
	}
	for _, c := range []struct {
		name string
		rows []string
		fn   func(string, string) bool
	}{
		{"subset colon", v.SubsetColon, func(p, c string) bool { return ResourceSubset(Colon, p, c) }},
		{"subset path", v.SubsetPath, func(p, c string) bool { return ResourceSubset(Path, p, c) }},
		{"overlap colon", v.OverlapColon, func(p, c string) bool { return ResourcesOverlap(Colon, p, c) }},
		{"overlap path", v.OverlapPath, func(p, c string) bool { return ResourcesOverlap(Path, p, c) }},
	} {
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
	if len(v.Perms) < 20 {
		t.Fatalf("only %d permission cases", len(v.Perms))
	}
	for i, pc := range v.Perms {
		conv := func(in []struct {
			Resource string   `json:"resource"`
			Actions  []string `json:"actions"`
		}) []Permission {
			out := make([]Permission, len(in))
			for k, p := range in {
				out[k] = Permission{Resource: p.Resource, Actions: p.Actions}
			}
			return out
		}
		if got := PermissionSubset(Resolve(pc.Mode), conv(pc.Parent), conv(pc.Child)); got != pc.Want {
			t.Errorf("perm case %d (%s) = %v, TS says %v", i, pc.Mode, got, pc.Want)
		}
	}
}

// TestNoShorterPrefixTwin guards the TS bug where a parent that is a shorter exact prefix of the
// child (parentParts.length <= childParts.length) counted as a superset.
func TestNoShorterPrefixTwin(t *testing.T) {
	for _, m := range []Mode{Colon, Path} {
		if ResourceSubset(m, "a:b", "a:b:c") {
			t.Errorf("%s: parent a:b must not cover child a:b:c", m)
		}
		if ResourceSubset(m, "mcp:github", "mcp:github:read") {
			t.Errorf("%s: parent mcp:github must not cover mcp:github:read", m)
		}
		if PermissionSubset(m,
			[]Permission{{Resource: "a:b", Actions: []string{"read"}}},
			[]Permission{{Resource: "a:b:c", Actions: []string{"read"}}}) {
			t.Errorf("%s: permission subset let a child widen a shorter parent", m)
		}
		if !ResourceSubset(m, "a:*", "a:b:c") {
			t.Errorf("%s: a:* must cover a:b:c", m)
		}
	}
	if !LegacyContains("a:b", "a:b:c") {
		t.Error("LegacyContains keeps the old over matching, used only for constraint inheritance")
	}
}

func TestPathSubsetWidening(t *testing.T) {
	if ResourceSubset(Path, "ros2:/fleet/*/cmd", "ros2:/fleet/**") {
		t.Error("a ** child must not fit under a one segment parent")
	}
	if ResourceSubset(Path, "ros2:/fleet/**", "ros2:/fleet/a/../../admin") {
		t.Error("traversal must not ride a glob")
	}
	if !ResourceSubset(Path, "ros2:/fleet/**", "ros2:/fleet/*") {
		t.Error("** covers *")
	}
	if ResourceSubset(Colon, "ros2:/fleet/**", "ros2:/fleet/a/cmd") {
		t.Error("colon mode treats /fleet/** as literal text")
	}
}
