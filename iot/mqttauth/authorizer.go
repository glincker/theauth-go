package mqttauth

import (
	"context"
	"strings"

	"github.com/glincker/theauth-go/v2/policy"
)

// ResourcePrefix starts every policy resource for an MQTT topic. The naming follows the device
// identity design (decision D8): the topic levels are colon segments, so the topic
// "sensors/temp/42" is the resource "mqtt:sensors:temp:42" and the filter "sensors/#" is
// "mqtt:sensors:*". See TopicResource.
const ResourcePrefix = "mqtt:"

// Decision is an authorization outcome with an audit reason. The reason never goes to the broker.
type Decision struct {
	Allowed bool
	Reason  string
	// Code is the machine readable outcome, one of the Code constants. Empty is read as
	// CodeAllowed for an allow and CodeNoPermission for a deny.
	Code string
}

func (d Decision) code() string {
	switch {
	case d.Code != "":
		return d.Code
	case d.Allowed:
		return CodeAllowed
	}
	return CodeNoPermission
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
				return Decision{Reason: "explicit deny", Code: CodeNoPermission}
			}
		case Allow:
			if action == ActionPublish && MatchTopic(f, topic) || action == ActionSubscribe && FilterCovers(f, topic) {
				allowed = true
			}
		}
	}
	if allowed {
		return Decision{Allowed: true, Reason: "allow rule", Code: CodeAllowed}
	}
	return Decision{Reason: "no matching allow rule", Code: CodeNoPermission}
}

// TopicResource converts a topic name or filter into the policy resource of decision D8:
// "sensors/temp/42" becomes "mqtt:sensors:temp:42" and a trailing "#" becomes "*". The single
// level wildcard "+" also becomes "*" (a policy star spans the rest of the resource, so this can
// only ever widen the request, and an allow must then cover everything below that level). A level
// that contains ":" cannot be told apart from a level boundary, so it is refused and ok is false.
func TopicResource(topic string) (string, bool) {
	levels := strings.Split(topic, "/")
	out := make([]string, len(levels))
	for i, l := range levels {
		switch {
		case strings.Contains(l, ":"):
			return "", false
		case l == "+" || l == "#":
			out[i] = "*"
		default:
			out[i] = l
		}
	}
	return ResourcePrefix + strings.Join(out, ":"), true
}

// PolicyAuthorizer evaluates the theAuth policy engine. The request resource is TopicResource of
// the topic (for example "mqtt:sensors:temp:42") and the action is "publish" or "subscribe". The
// attributes device_id and org_id are available for {var} substitution in statements.
//
// The policy glob "*" matches the MQTT wildcards textually, so an allow on "mqtt:a:*" covers the
// filter "a/#". The TypeScript matcher lets "mqtt:a:*" match "mqtt:a" too, as MQTT does for "a/#"
// and "a", so the authorizer evaluates the resource with and without a trailing colon: a deny on
// either wins, an allow on either grants. A glob cannot see that the filter "#" overlaps a deny on
// "mqtt:secret:*", so for wildcard subscriptions this authorizer also converts every deny (and
// escalate, which has no human to ask at a broker) resource into a filter and refuses on any
// overlap.
type PolicyAuthorizer struct {
	Evaluator policy.Evaluator
	// Policies returns the policies that apply to the device. An error denies.
	Policies func(ctx context.Context, d *Device) ([]*policy.Policy, error)
}

// Authorize implements Authorizer.
func (p PolicyAuthorizer) Authorize(ctx context.Context, d *Device, action Action, topic string) Decision {
	if p.Policies == nil {
		return Decision{Reason: "no policy source", Code: CodeIndeterminate}
	}
	pols, err := p.Policies(ctx, d)
	if err != nil {
		return Decision{Reason: "policy source error", Code: CodeIndeterminate}
	}
	res, ok := TopicResource(topic)
	if !ok {
		return Decision{Reason: "topic level contains a colon", Code: CodeNoPermission}
	}
	attrs := map[string]string{"device_id": d.ID, "org_id": d.OrgID}
	dec := p.Evaluator.Evaluate(policy.Request{Action: string(action), Resource: res, Attributes: attrs}, pols...)
	// The parent level of "a:*" is "a:". Evaluating it too gives the TypeScript semantics.
	alt := p.Evaluator.Evaluate(policy.Request{Action: string(action), Resource: res + ":", Attributes: attrs}, pols...)
	switch {
	case dec.Effect == policy.Deny:
	case alt.Effect == policy.Deny:
		dec = alt
	case !dec.Allowed && alt.Allowed:
		dec = alt
	}
	if !dec.Allowed {
		return Decision{Reason: dec.Reason, Code: string(dec.Code)}
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
				for _, r := range st.Resources {
					rest, ok := strings.CutPrefix(r, ResourcePrefix)
					if ok && FiltersOverlap(globToFilter(rest), topic) {
						return Decision{Reason: "wildcard subscription overlaps a deny", Code: CodeNoPermission}
					}
				}
			}
		}
	}
	return Decision{Allowed: true, Reason: "policy allow", Code: CodeAllowed}
}

func statementHasAction(st policy.Statement, action string) bool {
	for _, a := range st.Actions {
		if policy.Match(a, action) {
			return true
		}
	}
	return false
}

// globToFilter turns a policy resource glob (without the "mqtt:" prefix) into a superset MQTT
// filter: a segment holding "*" becomes "#" and ends the filter (a glob star spans the rest), a
// segment holding a {var} placeholder becomes "+".
func globToFilter(glob string) string {
	segs := strings.Split(glob, ":")
	out := make([]string, 0, len(segs))
	for _, l := range segs {
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
