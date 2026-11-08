package dpop_test

import (
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/dpop"
)

// A proof is accepted while |now - iat| <= ProofMaxAge + ClockSkew, so its jti must be remembered for
// the same span. Before the fix the entry lived only until iat + ProofMaxAge, and a proof inside the
// skew allowance could be replayed as soon as its entry had expired.
func TestVerifyRemembersJTIForTheWholeSkewWindow(t *testing.T) {
	svc := newService(t, func(c *dpop.Config) {
		c.ProofMaxAge = 10 * time.Second
		c.ClockSkew = 5 * time.Second
	})
	now := time.Now().UTC()
	claims := baseClaims(now)
	claims.IAT = now.Add(-13 * time.Second).Unix() // older than ProofMaxAge, inside ProofMaxAge+ClockSkew
	proof, _, _ := signedProofES256(t, claims, nil)
	params := dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now}

	if _, err := svc.Verify(proof, params); err != nil {
		t.Fatalf("first verify inside the skew window: %v", err)
	}
	if _, err := svc.Verify(proof, params); !errors.Is(err, dpop.ErrReplay) {
		t.Fatalf("second verify = %v, want ErrReplay", err)
	}
}
