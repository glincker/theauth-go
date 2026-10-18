package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

func TestGateAuthorizeAgentExpiry(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	exp := c.now().Add(time.Hour)
	ag := &models.Agent{ID: ulid.New(), Status: models.AgentStatusActive, ExpiresAt: &exp}
	st := fakeStorage{agents: map[models.ULID]*models.Agent{ag.ID: ag}}
	eng := byAction{verdicts: map[string]PolicyVerdict{"ok": {Effect: VerdictAllow}}}
	ctx := context.Background()

	tests := []struct {
		name string
		cfg  GateConfig
	}{
		{"with policy engine", GateConfig{Storage: st, Engine: eng, Now: c.now}},
		{"rate limit only", GateConfig{Storage: st, RateLimit: ratelimit.Window{Requests: 100, Per: time.Minute}, Now: c.now}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c.t = time.Unix(1_700_000_000, 0)
			g := NewGate(tc.cfg)
			if err := g.Authorize(ctx, ag.ID.String(), "ok", "r"); err != nil {
				t.Fatalf("before expiry: %v", err)
			}
			c.add(time.Hour)
			err := g.Authorize(ctx, ag.ID.String(), "ok", "r")
			if !errors.Is(err, ErrAgentExpired) || !errors.Is(err, ErrAgentNotActive) {
				t.Fatalf("at expiry err = %v, want ErrAgentExpired matching ErrAgentNotActive", err)
			}
		})
	}
}

func TestGateAuthorizeMintAgentExpiry(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	exp := c.now().Add(time.Minute)
	ag := models.Agent{ID: ulid.New(), Status: models.AgentStatusActive, ExpiresAt: &exp}
	g := NewGate(GateConfig{RateLimit: ratelimit.Window{Requests: 100, Per: time.Minute}, Now: c.now})
	req := models.AgentMintRequest{Grant: models.AgentMintClientCredentials, Resource: "r", Scopes: []string{"s"}}
	if _, err := g.AuthorizeMint(context.Background(), ag, req); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	c.add(2 * time.Minute)
	if _, err := g.AuthorizeMint(context.Background(), ag, req); !errors.Is(err, models.ErrAgentExpired) {
		t.Fatalf("after expiry err = %v, want ErrAgentExpired", err)
	}
}

func TestAgentExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	past, future := now.Add(-time.Second), now.Add(time.Second)
	tests := []struct {
		name string
		exp  *time.Time
		want bool
	}{
		{"nil never expires", nil, false},
		{"future", &future, false},
		{"exactly now", &now, true},
		{"past", &past, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := (models.Agent{ExpiresAt: tc.exp}).AgentExpired(now); got != tc.want {
				t.Fatalf("AgentExpired = %v, want %v", got, tc.want)
			}
		})
	}
}
