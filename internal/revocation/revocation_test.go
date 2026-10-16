package revocation

import (
	"testing"

	"github.com/glincker/theauth-go/v2/internal/models"
)

func TestFromAuditMappings(t *testing.T) {
	tests := []struct {
		name   string
		action string
		target models.TargetRef
		md     map[string]any
		want   Event
		ok     bool
	}{
		{"org deactivation", "scim.user.org_deactivated", models.TargetRef{Type: "user", ID: "u1"}, map[string]any{"detail": "o1"}, Event{Kind: OrgMember, ID: "o1", UserID: "u1", Reason: "scim.user.org_deactivated"}, true},
		{"org deactivation without org", "scim.user.org_deactivated", models.TargetRef{Type: "user", ID: "u1"}, nil, Event{}, false},
		{"minted token revoked", "api_token.revoked", models.TargetRef{Type: "api_token", ID: "t1"}, nil, Event{Kind: APIToken, ID: "t1", Reason: "api_token.revoked"}, true},
		{"cascade", "agent.cascade.revoked", models.TargetRef{Type: "agent", ID: "a1"}, nil, Event{Kind: Agent, ID: "a1", Reason: "agent.cascade.revoked"}, true},
		{"unrelated", "scim.user.create", models.TargetRef{Type: "user", ID: "u1"}, nil, Event{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := FromAudit(tc.action, tc.target, tc.md)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("FromAudit = %+v, %v; want %+v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestOrgMemberMatches(t *testing.T) {
	ev := Event{Kind: OrgMember, ID: "o1", UserID: "u1"}
	tests := []struct {
		name string
		t    Target
		want bool
	}{
		{"same org and user", Target{UserID: "u1", OrganizationID: "o1"}, true},
		{"other org", Target{UserID: "u1", OrganizationID: "o2"}, false},
		{"other user", Target{UserID: "u2", OrganizationID: "o1"}, false},
		{"unscoped stream", Target{UserID: "u1"}, false},
	}
	for _, tc := range tests {
		if got := tc.t.Matches(ev); got != tc.want {
			t.Errorf("%s: Matches = %v, want %v", tc.name, got, tc.want)
		}
	}
}
