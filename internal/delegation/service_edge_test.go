package delegation

import (
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// TestActiveBoundaries pins the revoked, nil, and expires_at edges.
func TestActiveBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	revoked := now.Add(-time.Minute)
	exp := now
	later := now.Add(time.Hour)
	tests := []struct {
		name string
		g    *models.DelegationGrant
		want bool
	}{
		{"nil grant", nil, false},
		{"revoked", &models.DelegationGrant{RevokedAt: &revoked}, false},
		{"no expiry", &models.DelegationGrant{}, true},
		{"expires exactly now is inactive", &models.DelegationGrant{ExpiresAt: &exp}, false},
		{"expires later is active", &models.DelegationGrant{ExpiresAt: &later}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Active(tt.g, now); got != tt.want {
				t.Fatalf("Active = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNarrowScopeEdges covers the empty-request fallback and strict subsets.
func TestNarrowScopeEdges(t *testing.T) {
	tests := []struct {
		name      string
		requested []string
		subject   []string
		grant     []string
		want      []string
		wantOK    bool
	}{
		{"empty request uses subject intersect grant", nil, []string{"a", "b"}, []string{"b", "c"}, []string{"b"}, true},
		{"empty subject falls back to grant", nil, nil, []string{"b", "c"}, []string{"b", "c"}, true},
		{"empty everything yields empty allowed", nil, nil, nil, []string{}, true},
		{"requested within both", []string{"a"}, []string{"a", "b"}, []string{"a"}, []string{"a"}, true},
		{"requested beyond subject denied", []string{"c"}, []string{"a"}, []string{"c"}, nil, false},
		{"requested beyond grant denied", []string{"a"}, []string{"a"}, []string{"b"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NarrowScope(tt.requested, tt.subject, tt.grant)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("scope = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("scope = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
