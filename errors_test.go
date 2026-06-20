package theauth_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/glincker/theauth-go"
)

func TestTheAuthErrorErrorString(t *testing.T) {
	e := theauth.NewError(theauth.CodeWeakPassword, "min 12 chars", nil)
	if got := e.Error(); got != "theauth: weak_password: min 12 chars" {
		t.Fatalf("got %q", got)
	}
	// No message → just code prefix.
	e2 := theauth.NewError(theauth.CodeRateLimited, "", nil)
	if got := e2.Error(); got != "theauth: rate_limited" {
		t.Fatalf("got %q", got)
	}
}

func TestTheAuthErrorUnwrap(t *testing.T) {
	root := errors.New("db down")
	e := theauth.NewError(theauth.CodeInvalidCredentials, "lookup failed", root)
	if !errors.Is(e, root) {
		t.Fatal("errors.Is should walk through Unwrap")
	}
}

// Two TheAuthErrors with the same Code should be Is-equal even when the
// message and inner cause differ. This is the public contract callers rely on.
func TestTheAuthErrorIsByCode(t *testing.T) {
	a := theauth.NewError(theauth.CodeEmailTaken, "exists", fmt.Errorf("pg unique violation"))
	target := &theauth.TheAuthError{Code: theauth.CodeEmailTaken}
	if !errors.Is(a, target) {
		t.Fatal("expected errors.Is to match by Code")
	}
	other := &theauth.TheAuthError{Code: theauth.CodeWeakPassword}
	if errors.Is(a, other) {
		t.Fatal("different Code should not match")
	}
}

func TestTheAuthErrorAs(t *testing.T) {
	wrapped := fmt.Errorf("call site: %w", theauth.NewError(theauth.CodeWeakPassword, "too short", nil))
	var got *theauth.TheAuthError
	if !errors.As(wrapped, &got) {
		t.Fatal("errors.As should extract *TheAuthError")
	}
	if got.Code != theauth.CodeWeakPassword {
		t.Fatalf("got Code=%q", got.Code)
	}
}

func TestTheAuthErrorNilSafe(t *testing.T) {
	var e *theauth.TheAuthError
	if e.Error() != "" {
		t.Fatal("nil receiver Error() should be empty")
	}
	if e.Unwrap() != nil {
		t.Fatal("nil receiver Unwrap() should be nil")
	}
	if e.Is(errors.New("x")) {
		t.Fatal("nil receiver Is() should be false")
	}
}
