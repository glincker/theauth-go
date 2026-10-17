package toolguard

import (
	"context"
	"errors"
	"testing"

	"github.com/glincker/theauth-go/v2/policy"
)

func TestGuardLimitHook(t *testing.T) {
	allow := &policy.Policy{Version: policy.Version, Statements: []policy.Statement{{Effect: policy.Allow, Actions: []string{"*"}, Resources: []string{"*"}}}}
	errLimited := errors.New("limited")
	calls := 0
	g := &Guard{
		Policies: func(context.Context, string) ([]*policy.Policy, error) { return []*policy.Policy{allow}, nil },
		Limit: func(_ context.Context, id string) error {
			calls++
			if calls > 1 {
				return errLimited
			}
			return nil
		},
	}
	if err := g.Authorize(context.Background(), Call{AgentID: "a", Tool: "t"}); err != nil {
		t.Fatal(err)
	}
	err := g.Authorize(context.Background(), Call{AgentID: "a", Tool: "t"})
	if !errors.Is(err, ErrGuardFailed) || !errors.Is(err, errLimited) {
		t.Fatalf("want ErrGuardFailed wrapping the limit error, got %v", err)
	}
}
