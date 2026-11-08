package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func newDecisionAuth(t *testing.T, failClosed bool) *theauth.TheAuth {
	t.Helper()
	a, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		Audit: &theauth.AuditConfig{FlushInterval: 10 * time.Millisecond, FailClosed: failClosed},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestTheAuth_EmitDecision_Forwards(t *testing.T) {
	ctx := context.Background()
	a := newDecisionAuth(t, true)
	if err := a.EmitDecision(ctx, "policy.evaluated", theauth.TargetRef{Type: "tool", ID: "x"}, nil); err != nil {
		t.Fatalf("EmitDecision while healthy = %v, want nil", err)
	}
	a.Close()
	// Stopped service: a decision-class event fails closed, others do not.
	err := a.EmitDecision(ctx, "policy.evaluated", theauth.TargetRef{}, nil)
	if !errors.Is(err, theauth.ErrAuditUnavailable) {
		t.Fatalf("EmitDecision after Close = %v, want ErrAuditUnavailable", err)
	}
	if err := a.EmitDecision(ctx, "user.login", theauth.TargetRef{}, nil); err != nil {
		t.Fatalf("non-decision action = %v, want nil", err)
	}
}

func TestTheAuth_EmitDecision_OpenByDefault(t *testing.T) {
	a := newDecisionAuth(t, false)
	a.Close()
	if err := a.EmitDecision(context.Background(), "policy.evaluated", theauth.TargetRef{}, nil); err != nil {
		t.Fatalf("EmitDecision without FailClosed = %v, want nil", err)
	}
}

// noChainStore is a memory store that hides its chain, standing in for a backend without one.
type noChainStore struct{ *memory.Store }

func (noChainStore) ChainSupported() bool { return false }

func TestTheAuth_VerifyAuditChain_MemoryIsChained(t *testing.T) {
	a := newDecisionAuth(t, false)
	defer a.Close()
	res, err := a.VerifyAuditChain(context.Background())
	if err != nil || !res.Supported || !res.OK {
		t.Fatalf("memory chain = %+v, %v", res, err)
	}
}

func TestTheAuth_VerifyAuditChain_UnsupportedBackend(t *testing.T) {
	a, err := theauth.New(theauth.Config{
		Storage: noChainStore{memory.New()}, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	res, err := a.VerifyAuditChain(context.Background())
	if !errors.Is(err, theauth.ErrAuditChainUnsupported) {
		t.Fatalf("err = %v, want ErrAuditChainUnsupported", err)
	}
	if res.Supported || res.OK {
		t.Fatalf("unsupported backend must not report a pass: %+v", res)
	}
}
