package device

import (
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/policy/pathmatch"
)

// TestBundleResourceMatchingClaim signs a bundle with and without the rm claim and checks that
// Evaluate follows what was signed.
func TestBundleResourceMatchingClaim(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	s := newKeys(t)["EdDSA"]
	perm := Permission{Resource: "ros2:/fleet/*/cmd", Actions: []string{"publish"}}
	pub := s.Public()
	pub.KID = "k1"

	verify := func(t *testing.T, mode pathmatch.Mode) *Claims {
		t.Helper()
		c := testClaims("dev-1", now, perm)
		c.ResourceMatching = mode
		tok, err := s.SignBundle("k1", c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := VerifyBundle(tok, VerifyOptions{Keys: NewKeySet(pub), DeviceID: "dev-1", Now: now})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	t.Run("path", func(t *testing.T) {
		got := verify(t, pathmatch.Path)
		if got.ResourceMatching != pathmatch.Path {
			t.Fatalf("rm lost: %q", got.ResourceMatching)
		}
		if d := Evaluate(got, "publish", "ros2:/fleet/a/cmd", WithNow(now)); !d.Allowed {
			t.Fatalf("one segment denied: %+v", d)
		}
		for _, res := range []string{"ros2:/fleet/a/b/cmd", "ros2:/fleet/../cmd", "ros2:/fleet//cmd"} {
			if d := Evaluate(got, "publish", res, WithNow(now)); d.Allowed || d.Code != CodeNoPermission {
				t.Fatalf("%s: want no_permission, got %+v", res, d)
			}
		}
	})

	t.Run("colon default", func(t *testing.T) {
		got := verify(t, "")
		if got.ResourceMatching != pathmatch.Colon {
			t.Fatalf("default mode %q", got.ResourceMatching)
		}
		if d := Evaluate(got, "publish", "ros2:/fleet/a/cmd", WithNow(now)); d.Allowed {
			t.Fatalf("a path star must be literal text in colon mode: %+v", d)
		}
		if d := Evaluate(got, "publish", "ros2:/fleet/*/cmd", WithNow(now)); !d.Allowed {
			t.Fatalf("literal match denied: %+v", d)
		}
	})
}
