package mqttauth

import (
	"context"
	"errors"
	"testing"

	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/policy/pathmatch"
)

func TestPolicyAuthorizer(t *testing.T) {
	pol := &policy.Policy{Version: "1", ID: "iot", Statements: []policy.Statement{
		{Effect: policy.Allow, Actions: []string{"publish"}, Resources: []string{"mqtt:devices:{device_id}:telemetry:*"}},
		{Effect: policy.Allow, Actions: []string{"subscribe"}, Resources: []string{"mqtt:fleet:*", "mqtt:devices:{device_id}:cmd:*"}},
		{Effect: policy.Deny, Actions: []string{"subscribe", "publish"}, Resources: []string{"mqtt:fleet:secret:*"}},
	}}
	a := PolicyAuthorizer{Policies: func(context.Context, *Device) ([]*policy.Policy, error) { return []*policy.Policy{pol}, nil }}
	d := &Device{ID: "dev1", OrgID: "o"}
	cases := []struct {
		action Action
		topic  string
		want   bool
	}{
		{ActionPublish, "devices/dev1/telemetry/t", true},
		{ActionPublish, "devices/dev2/telemetry/t", false},
		{ActionPublish, "fleet/secret/x", false},
		{ActionSubscribe, "fleet/a/b", true},
		{ActionSubscribe, "fleet/#", false}, // overlaps the deny on fleet/secret
		{ActionSubscribe, "fleet/+/x", false},
		{ActionSubscribe, "fleet/public/#", true},
		{ActionSubscribe, "fleet/secret/k", false},
		{ActionSubscribe, "devices/dev1/cmd/#", true},
		{ActionSubscribe, "#", false},
		{ActionPublish, "devices/dev1/telemetry", true}, // "x/#" matches "x" in MQTT, "x:*" matches "x" in TypeScript
		{ActionSubscribe, "fleet", true},
		{ActionPublish, "fleet/secret", false}, // the deny on fleet:secret:* covers the parent
		{ActionPublish, "devices/dev1/cmd:x/y", false},
	}
	for _, c := range cases {
		if got := a.Authorize(context.Background(), d, c.action, c.topic).Allowed; got != c.want {
			t.Errorf("%s %q = %v, want %v", c.action, c.topic, got, c.want)
		}
	}
	failing := PolicyAuthorizer{Policies: func(context.Context, *Device) ([]*policy.Policy, error) { return nil, errors.New("x") }}
	if failing.Authorize(context.Background(), d, ActionPublish, "a").Allowed {
		t.Error("policy source error allowed")
	}
	if (PolicyAuthorizer{}).Authorize(context.Background(), d, ActionPublish, "a").Allowed {
		t.Error("nil policy source allowed")
	}
}

func TestGlobToFilter(t *testing.T) {
	for in, want := range map[string]string{
		"fleet:secret:*": "fleet/secret/#", "a:*:b": "a/#", "a:{device_id}:b": "a/+/b", "a:b": "a/b", "*": "#", "a*:b": "#",
	} {
		if got := globToFilter(in); got != want {
			t.Errorf("globToFilter(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTopicResource(t *testing.T) {
	for in, want := range map[string]string{
		"sensors/temp/42": "mqtt:sensors:temp:42", "sensors/#": "mqtt:sensors:*", "#": "mqtt:*",
		"a/+/b": "mqtt:a:*:b", "$SYS/x": "mqtt:$SYS:x", "a//b": "mqtt:a::b",
	} {
		got, ok := TopicResource(in)
		if !ok || got != want {
			t.Errorf("TopicResource(%q) = %q, %v, want %q", in, got, ok, want)
		}
	}
	if _, ok := TopicResource("a/b:c"); ok {
		t.Error("a level with a colon must be refused")
	}
}

// TestPolicyAuthorizerPathMode checks that the evaluator's ResourceMatching reaches the broker
// authorizer: a middle "*" is one non empty level, a partial glob is literal text.
func TestPolicyAuthorizerPathMode(t *testing.T) {
	pol := &policy.Policy{Version: "1", ID: "iot", Statements: []policy.Statement{
		{Effect: policy.Allow, Actions: []string{"publish"}, Resources: []string{"mqtt:fleet:*:cmd", "mqtt:lab:r*"}},
	}}
	pols := func(context.Context, *Device) ([]*policy.Policy, error) { return []*policy.Policy{pol}, nil }
	glob := PolicyAuthorizer{Policies: pols}
	path := PolicyAuthorizer{Evaluator: policy.Evaluator{ResourceMatching: pathmatch.Path}, Policies: pols}
	d := &Device{ID: "dev1", OrgID: "o"}
	cases := []struct {
		topic      string
		glob, path bool
	}{
		{"fleet/a/cmd", true, true},
		{"fleet/a/b/cmd", true, false}, // the glob star spans levels
		{"fleet//cmd", true, false},    // and an empty one
		{"lab/robot", true, false},     // "r*" is literal in path mode
		{"lab/r*", true, true},
	}
	for _, c := range cases {
		if got := glob.Authorize(context.Background(), d, ActionPublish, c.topic).Allowed; got != c.glob {
			t.Errorf("glob mode %q = %v, want %v", c.topic, got, c.glob)
		}
		if got := path.Authorize(context.Background(), d, ActionPublish, c.topic).Allowed; got != c.path {
			t.Errorf("path mode %q = %v, want %v", c.topic, got, c.path)
		}
	}
}
