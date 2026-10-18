package mqttauth

import (
	"context"
	"strings"

	"github.com/glincker/theauth-go/v2/policy"
)

// Resource and action names used when the decision goes through the policy engine.
const (
	ResourcePrefix = "mqtt:topic/"
)

// Decision is an authorization outcome with an audit reason. The reason never goes to the broker.
type Decision struct {
	Allowed bool
	Reason  string
}

// Authorizer decides whether a device may publish to a topic name or subscribe with a filter.
// For ActionPublish topic is a topic name, for ActionSubscribe a topic filter with any $share
// prefix already removed. Both are validated before the call. Implementations must fail closed.
type Authorizer interface {
	Authorize(ctx context.Context, d *Device, action Action, topic string) Decision
}

// RuleAuthorizer applies Device.Rules: deny rules first, then allow rules. For a subscription
// an allow rule must cover the whole requested filter and a deny rule blocks it when the filters
// overlap at all, so subscribing to "#" cannot sneak past a deny on "secret/#".
type RuleAuthorizer struct{}

// Authorize implements Authorizer.
func (RuleAuthorizer) Authorize(_ context.Context, d *Device, action Action, topic string) Decision {
	repl := strings.NewReplacer("{device_id}", d.ID, "{org_id}", d.OrgID)
	allowed := false
	for _, r := range d.Rules {
		if r.Action != ActionAll && r.Action != action {
			continue
		}
		f := repl.Replace(r.Filter)
		if strings.Contains(r.Filter, "{org_id}") && d.OrgID == "" {
			continue
		}
		if ValidateFilter(f) != nil {
			continue
		}
		switch r.Effect {
		case Deny:
			if action == ActionPublish && MatchTopic(f, topic) || action == ActionSubscribe && FiltersOverlap(f, topic) {
				return Decision{Reason: "explicit deny"}
			}
		case Allow:
			if action == ActionPublish && MatchTopic(f, topic) || action == ActionSubscribe && FilterCovers(f, topic) {
				allowed = true
			}
		}
	}
	if allowed {
		return Decision{Allowed: true, Reason: "allow rule"}
	}
	return Decision{Reason: "no matching allow rule"}
}

// PolicyAuthorizer evaluates the theAuth policy engine. The request resource is
// "mqtt:topic/<name or filter>" and the action is "publish" or "subscribe". The attributes
// device_id and org_id are available for {var} substitution in statements.
//
// The policy glob "*" matches the MQTT wildcards textually, so an allow on "mqtt:topic/a/*"
// covers the filter "a/#". A glob cannot see that the filter "#" overlaps a deny on
// "mqtt:topic/secret/*", so for wildcard subscriptions this authorizer also converts every deny
// (and escalate, which has no human to ask at a broker) resource into a filter and refuses on any
// overlap.
type PolicyAuthorizer struct {
	Evaluator policy.Evaluator
	// Policies returns the policies that apply to the device. An error denies.
	Policies func(ctx context.Context, d *Device) ([]*policy.Policy, error)
}

// Authorize implements Authorizer.
func (p PolicyAuthorizer) Authorize(ctx context.Context, d *Device, action Action, topic string) Decision {
	if p.Policies == nil {
		return Decision{Reason: "no policy source"}
	}
	pols, err := p.Policies(ctx, d)
	if err != nil {
		return Decision{Reason: "policy source error"}
	}
	dec := p.Evaluator.Evaluate(policy.Request{
		Action:     string(action),
		Resource:   ResourcePrefix + topic,
		Attributes: map[string]string{"device_id": d.ID, "org_id": d.OrgID},
	}, pols...)
	if !dec.Allowed {
		return Decision{Reason: dec.Reason}
	}
	if action == ActionSubscribe && strings.ContainsAny(topic, "+#") {
		for _, pol := range pols {
			if pol == nil {
				continue
			}
			for _, st := range pol.Statements {
				if st.Effect == policy.Allow || !statementHasAction(st, string(action)) {
					continue
				}
				for _, res := range st.Resources {
					rest, ok := strings.CutPrefix(res, ResourcePrefix)
					if ok && FiltersOverlap(globToFilter(rest), topic) {
						return Decision{Reason: "wildcard subscription overlaps a deny"}
					}
				}
			}
		}
	}
	return Decision{Allowed: true, Reason: "policy allow"}
}

func statementHasAction(st policy.Statement, action string) bool {
	for _, a := range st.Actions {
		if policy.Match(a, action) {
			return true
		}
	}
	return false
}

// globToFilter turns a policy resource glob into a superset MQTT filter: a level holding "*"
// becomes "#" and ends the filter (a glob star also spans "/"), a level holding a {var}
// placeholder becomes "+".
func globToFilter(glob string) string {
	levels := strings.Split(glob, "/")
	out := make([]string, 0, len(levels))
	for _, l := range levels {
		switch {
		case strings.Contains(l, "*"):
			return strings.Join(append(out, "#"), "/")
		case strings.Contains(l, "{"):
			out = append(out, "+")
		case strings.ContainsAny(l, "+#"):
			out = append(out, "+")
		default:
			out = append(out, l)
		}
	}
	return strings.Join(out, "/")
}
