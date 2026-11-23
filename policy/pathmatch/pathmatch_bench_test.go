package pathmatch

import "testing"

func benchMode(b *testing.B, mode Mode, pattern, resource string, want bool) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if Match(mode, pattern, resource) != want {
			b.Fatal("unexpected result")
		}
	}
}

func BenchmarkMatchColonExact(b *testing.B) {
	benchMode(b, Colon, "mqtt:sensors:temp:42", "mqtt:sensors:temp:42", true)
}
func BenchmarkMatchColonStar(b *testing.B) {
	benchMode(b, Colon, "mqtt:sensors:*", "mqtt:sensors:temp:42", true)
}
func BenchmarkMatchColonMiss(b *testing.B) {
	benchMode(b, Colon, "mqtt:sensors:temp:1", "mqtt:sensors:temp:42", false)
}
func BenchmarkMatchPathExact(b *testing.B) {
	benchMode(b, Path, "ros2:/fleet/a/cmd_vel", "ros2:/fleet/a/cmd_vel", true)
}
func BenchmarkMatchPathSegmentWildcard(b *testing.B) {
	benchMode(b, Path, "ros2:/fleet/*/cmd_vel", "ros2:/fleet/a/cmd_vel", true)
}
func BenchmarkMatchPathDoubleStar(b *testing.B) {
	benchMode(b, Path, "ros2:/fleet/**", "ros2:/fleet/a/b/c/cmd_vel", true)
}
func BenchmarkMatchPathDoubleStarMid(b *testing.B) {
	benchMode(b, Path, "ros2:/fleet/**/cmd_vel", "ros2:/fleet/a/b/c/cmd_vel", true)
}
func BenchmarkMatchPathMiss(b *testing.B) {
	benchMode(b, Path, "ros2:/fleet/*/cmd_vel", "ros2:/fleet/a/../admin", false)
}

func benchPerms(n int, suffix string) []Permission {
	out := make([]Permission, n)
	for i := range out {
		out[i] = Permission{Resource: "svc" + string(rune('a'+i%26)) + suffix, Actions: []string{"read", "write"}}
	}
	return out
}

// BenchmarkPermissionSubset is the delegation check: every child permission must be covered by a
// parent permission.
func BenchmarkPermissionSubset(b *testing.B) {
	cases := []struct {
		mode          Mode
		parent, child []Permission
	}{
		{Colon, benchPerms(20, ":*"), []Permission{
			{Resource: "svcc:x:y", Actions: []string{"read"}},
			{Resource: "svcs:z", Actions: []string{"read", "write"}},
			{Resource: "svct:*", Actions: []string{"write"}},
		}},
		{Path, benchPerms(20, ":/data/**"), []Permission{
			{Resource: "svcc:/data/x/y", Actions: []string{"read"}},
			{Resource: "svcs:/data/z", Actions: []string{"read", "write"}},
			{Resource: "svct:/data/**", Actions: []string{"write"}},
		}},
	}
	for _, c := range cases {
		b.Run(string(c.mode), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !PermissionSubset(c.mode, c.parent, c.child) {
					b.Fatal("not a subset")
				}
			}
		})
	}
}

func BenchmarkResourcesOverlapPath(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !ResourcesOverlap(Path, "ros2:/fleet/*/cmd_vel", "ros2:/fleet/a/**") {
			b.Fatal("want overlap")
		}
	}
}
