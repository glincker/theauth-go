package theauth_test

import (
	"context"
	"testing"

	"github.com/glincker/theauth-go"
)

func TestRequestMagicLinkCreatesAndEmails(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	if _, err := theauth.RequestMagicLinkForTest(a, ctx, "x@y.com"); err != nil {
		t.Fatal(err)
	}
}

func TestConsumeMagicLinkCreatesUserAndSession(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	token, err := theauth.RequestMagicLinkForTest(a, ctx, "consume@y.com")
	if err != nil {
		t.Fatal(err)
	}
	sessToken, user, err := theauth.ConsumeMagicLinkForTest(a, ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if sessToken == "" {
		t.Fatal("expected session token")
	}
	if user.Email != "consume@y.com" {
		t.Fatalf("got user email %q", user.Email)
	}
}

func TestConsumeMagicLinkTwiceFails(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	token, _ := theauth.RequestMagicLinkForTest(a, ctx, "twice@y.com")
	if _, _, err := theauth.ConsumeMagicLinkForTest(a, ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, _, err := theauth.ConsumeMagicLinkForTest(a, ctx, token); err == nil {
		t.Fatal("expected error on second consume")
	}
}
