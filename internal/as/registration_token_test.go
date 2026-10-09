package as_test

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

type auditRec struct {
	mu     sync.Mutex
	events []string
}

func (a *auditRec) EmitAudit(_ context.Context, action string, _ models.TargetRef, _ map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, action)
}

func (a *auditRec) has(action string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e == action {
			return true
		}
	}
	return false
}

func newRegService(t *testing.T) (*internalas.Service, *fakeClock, *auditRec) {
	t.Helper()
	clock := newFakeClock(time.Now())
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cfg := internalas.Config{
		Issuer:          "https://auth.example.com",
		Resources:       []models.ProtectedResource{{Identifier: "https://files.example.com/mcp", Scopes: []string{"files.read"}}},
		DisableRotation: true,
		Clock:           clock,
	}
	if err := internalas.Validate(&cfg, key); err != nil {
		t.Fatal(err)
	}
	rec := &auditRec{}
	svc := internalas.New(internalas.Deps{Cfg: cfg, Storage: memory.New(), EncryptionKey: key, Audit: rec})
	return svc, clock, rec
}

func TestRegistrationTokenCreate(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		in      internalas.CreateRegistrationTokenInput
		wantErr bool
		maxUses int
		ttl     time.Duration
	}{
		{"defaults to one use and the configured ttl", internalas.CreateRegistrationTokenInput{Label: "ci"}, false, 1, 24 * time.Hour},
		{"explicit uses and ttl", internalas.CreateRegistrationTokenInput{MaxUses: 5, TTL: time.Hour}, false, 5, time.Hour},
		{"negative uses rejected", internalas.CreateRegistrationTokenInput{MaxUses: -1}, true, 0, 0},
		{"absurd uses rejected", internalas.CreateRegistrationTokenInput{MaxUses: 100000}, true, 0, 0},
		{"negative ttl rejected", internalas.CreateRegistrationTokenInput{TTL: -time.Second}, true, 0, 0},
		{"unknown grant type rejected", internalas.CreateRegistrationTokenInput{GrantTypes: []string{"password"}}, true, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, clock, rec := newRegService(t)
			tok, raw, err := svc.CreateRegistrationToken(ctx, tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(raw, "rt_") || len(raw) < 40 {
				t.Fatalf("token shape: %q", raw)
			}
			if tok.MaxUses != tc.maxUses || !tok.ExpiresAt.Equal(clock.Now().UTC().Add(tc.ttl)) {
				t.Fatalf("stored token: %+v", tok)
			}
			if strings.Contains(string(tok.TokenHash), raw) || tok.Prefix == raw {
				t.Fatal("plaintext leaked into the record")
			}
			if !rec.has("oauth.registration_token.created") {
				t.Fatal("no audit event for creation")
			}
		})
	}
}

func TestRegistrationTokenRedeem(t *testing.T) {
	ctx := context.Background()
	type tcase struct {
		name    string
		in      internalas.CreateRegistrationTokenInput
		req     internalas.ClientRegistrationRequest
		mutate  func(svc *internalas.Service, clock *fakeClock, id models.ULID, raw *string)
		wantErr error
	}
	cases := []tcase{
		{name: "valid"},
		{name: "unknown token", mutate: func(_ *internalas.Service, _ *fakeClock, _ models.ULID, raw *string) { *raw = "rt_unknown" }, wantErr: models.ErrRegistrationTokenInvalid},
		{name: "not one of ours", mutate: func(_ *internalas.Service, _ *fakeClock, _ models.ULID, raw *string) { *raw = "static-token" }, wantErr: models.ErrRegistrationTokenInvalid},
		{name: "expired", mutate: func(_ *internalas.Service, c *fakeClock, _ models.ULID, _ *string) { c.Advance(25 * time.Hour) }, wantErr: models.ErrRegistrationTokenInvalid},
		{name: "revoked", mutate: func(s *internalas.Service, _ *fakeClock, id models.ULID, _ *string) {
			_ = s.RevokeRegistrationToken(ctx, id, nil, nil)
		}, wantErr: models.ErrRegistrationTokenInvalid},
		{name: "scope exceeded", in: internalas.CreateRegistrationTokenInput{Scopes: []string{"files.read"}},
			req: internalas.ClientRegistrationRequest{Scope: "files.read files.write"}, wantErr: models.ErrRegistrationTokenScope},
		{name: "scope within the cap", in: internalas.CreateRegistrationTokenInput{Scopes: []string{"files.read", "files.write"}},
			req: internalas.ClientRegistrationRequest{Scope: "files.read"}},
		{name: "grant type exceeded", in: internalas.CreateRegistrationTokenInput{GrantTypes: []string{"client_credentials"}},
			req: internalas.ClientRegistrationRequest{GrantTypes: []string{"client_credentials", "authorization_code"}}, wantErr: models.ErrRegistrationTokenScope},
		{name: "default grants count against the cap", in: internalas.CreateRegistrationTokenInput{GrantTypes: []string{"client_credentials"}},
			req: internalas.ClientRegistrationRequest{}, wantErr: models.ErrRegistrationTokenScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, clock, _ := newRegService(t)
			tok, raw, err := svc.CreateRegistrationToken(ctx, tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if tc.mutate != nil {
				tc.mutate(svc, clock, tok.ID, &raw)
			}
			got, err := svc.RedeemRegistrationToken(ctx, raw, tc.req)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && (got == nil || got.Uses != 1) {
				t.Fatalf("redeemed token: %+v", got)
			}
			if errors.Is(tc.wantErr, models.ErrRegistrationTokenScope) {
				stored, _ := svc.ListRegistrationTokens(ctx, nil)
				if stored[0].Uses != 0 {
					t.Fatal("a rejected request must not spend a use")
				}
			}
		})
	}

	t.Run("one-time token has one winner, refund reopens it", func(t *testing.T) {
		svc, _, _ := newRegService(t)
		tok, raw, _ := svc.CreateRegistrationToken(ctx, internalas.CreateRegistrationTokenInput{})
		first, err := svc.RedeemRegistrationToken(ctx, raw, internalas.ClientRegistrationRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.RedeemRegistrationToken(ctx, raw, internalas.ClientRegistrationRequest{}); !errors.Is(err, models.ErrRegistrationTokenInvalid) {
			t.Fatalf("second redeem: %v", err)
		}
		svc.RefundRegistrationToken(ctx, first.ID)
		if _, err := svc.RedeemRegistrationToken(ctx, raw, internalas.ClientRegistrationRequest{}); err != nil {
			t.Fatalf("after refund: %v", err)
		}
		_ = tok
	})
}

func TestRegistrationTokenRevokeAndAudit(t *testing.T) {
	ctx := context.Background()
	svc, _, rec := newRegService(t)
	org, other := ulid.New(), ulid.New()
	tok, raw, err := svc.CreateRegistrationToken(ctx, internalas.CreateRegistrationTokenInput{OrganizationID: &org})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeRegistrationToken(ctx, tok.ID, &other, nil); !errors.Is(err, models.ErrStorageNotFound) {
		t.Fatalf("other org must not see the token: %v", err)
	}
	if list, _ := svc.ListRegistrationTokens(ctx, &other); len(list) != 0 {
		t.Fatalf("other org lists %d tokens", len(list))
	}
	redeemed, err := svc.RedeemRegistrationToken(ctx, raw, internalas.ClientRegistrationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	svc.RegistrationSucceeded(ctx, redeemed, "client-1")
	if err := svc.RevokeRegistrationToken(ctx, tok.ID, &org, nil); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{"oauth.registration_token.created", "oauth.registration_token.redeemed", "oauth.registration_token.revoked"} {
		if !rec.has(ev) {
			t.Errorf("missing audit event %s (have %v)", ev, rec.events)
		}
	}
}
