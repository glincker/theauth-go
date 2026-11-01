package agentpolicy_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/glincker/theauth-go/v2/agentpolicy"
	"github.com/glincker/theauth-go/v2/internal/agent"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/policy"
)

// TestDecideHashIsSHA256OfPolicyJSON pins the policy hash that goes into audit and tokens: the
// SHA-256 of json.Marshal of every document, base policies first, each followed by a zero byte.
// The base documents are encoded once in New, so this guards that shortcut.
func TestDecideHashIsSHA256OfPolicyJSON(t *testing.T) {
	base := doc("base", policy.Statement{Effect: policy.Allow, Actions: []string{"a.*"}, Resources: []string{"*"}})
	extra := doc("extra", policy.Statement{ID: "d", Effect: policy.Deny, Actions: []string{"a.x"}, Resources: []string{"r:*"}})
	e, err := agentpolicy.New(agentpolicy.Config{
		Policies: []policy.Policy{base},
		Resolver: func(context.Context, models.Agent) ([]policy.Policy, error) { return []policy.Policy{extra}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	for _, p := range []policy.Policy{base, extra} {
		b, err := json.Marshal(&p)
		if err != nil {
			t.Fatal(err)
		}
		h.Write(b)
		h.Write([]byte{0})
	}
	want := hex.EncodeToString(h.Sum(nil))
	for i := 0; i < 2; i++ { // twice: the cached base bytes must not change between calls
		dec, err := e.Decide(context.Background(), models.Agent{ID: ulid.New()}, []agent.PolicyQuery{{Action: "a.y", Resource: "z"}})
		if err != nil {
			t.Fatal(err)
		}
		if dec.Hash != want {
			t.Fatalf("call %d: hash %s want %s", i, dec.Hash, want)
		}
		if len(dec.IDs) != 2 || dec.IDs[0] != "base" || dec.IDs[1] != "extra" {
			t.Fatalf("ids: %v", dec.IDs)
		}
	}
}
