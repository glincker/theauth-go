// Package mqttauth answers the authentication and authorization questions an MQTT broker asks
// over HTTP: may this client connect, and may it publish to or subscribe to this topic.
//
// It speaks the EMQX 5 HTTP authenticator and authorizer contracts and, behind a flag, the
// mosquitto-go-auth HTTP backend contract. Devices are principals from a DeviceStore. Every
// decision fails closed.
//
// Topic semantics follow MQTT 5.0 section 4.7 (topic names and filters), 4.7.2 (topics beginning
// with $) and 4.8.2 (shared subscriptions). MQTT 3.1.1 section 4.7 is identical for the parts used here.
package mqttauth

import (
	"errors"
	"strings"
)

const maxTopicLen = 65535

// ErrInvalidTopic wraps every topic name and topic filter validation failure.
var ErrInvalidTopic = errors.New("mqttauth: invalid topic")

func invalid(why string) error { return errors.Join(ErrInvalidTopic, errors.New(why)) }

// ValidateTopicName checks a PUBLISH topic name: not empty, no NUL, no wildcard characters
// (MQTT 5.0 section 3.3.2.1 and 4.7.1).
func ValidateTopicName(name string) error {
	if name == "" {
		return invalid("empty topic name")
	}
	if len(name) > maxTopicLen {
		return invalid("topic name too long")
	}
	if strings.ContainsRune(name, 0) {
		return invalid("topic name contains NUL")
	}
	if strings.ContainsAny(name, "+#") {
		return invalid("wildcard in topic name")
	}
	return nil
}

// ValidateFilter checks a topic filter (MQTT 5.0 section 4.7.1): "#" must stand alone as the last
// level and "+" must occupy a whole level. A "$share/" prefix is not interpreted here, see
// ParseSubscription.
func ValidateFilter(filter string) error {
	if filter == "" {
		return invalid("empty topic filter")
	}
	if len(filter) > maxTopicLen {
		return invalid("topic filter too long")
	}
	if strings.ContainsRune(filter, 0) {
		return invalid("topic filter contains NUL")
	}
	levels := strings.Split(filter, "/")
	for i, l := range levels {
		switch {
		case l == "#":
			if i != len(levels)-1 {
				return invalid("# must be the last level")
			}
		case l == "+":
		case strings.ContainsAny(l, "+#"):
			return invalid("wildcard must occupy a whole level")
		}
	}
	return nil
}

// Subscription is a parsed SUBSCRIBE topic filter.
type Subscription struct {
	// Filter is the topic filter with any shared subscription prefix removed.
	Filter string
	// Group is the share name of a shared subscription, empty otherwise.
	Group string
	// Shared reports whether the filter had the $share/{group}/ prefix.
	Shared bool
}

// ParseSubscription validates a subscription filter and strips the shared subscription prefix
// "$share/{ShareName}/{filter}" (MQTT 5.0 section 4.8.2). The share name must be non empty and
// contain no "/", "+" or "#".
func ParseSubscription(raw string) (Subscription, error) {
	if !strings.HasPrefix(raw, "$share/") {
		if raw == "$share" {
			return Subscription{}, invalid("malformed shared subscription")
		}
		if err := ValidateFilter(raw); err != nil {
			return Subscription{}, err
		}
		return Subscription{Filter: raw}, nil
	}
	rest := raw[len("$share/"):]
	group, filter, ok := strings.Cut(rest, "/")
	if !ok || group == "" || strings.ContainsAny(group, "+#") || strings.ContainsRune(group, 0) {
		return Subscription{}, invalid("malformed shared subscription")
	}
	if err := ValidateFilter(filter); err != nil {
		return Subscription{}, err
	}
	return Subscription{Filter: filter, Group: group, Shared: true}, nil
}

func isWild(level string) bool { return level == "+" || level == "#" }

// dollarLiteral reports whether a level is a literal beginning with "$".
func dollarLiteral(level string) bool { return strings.HasPrefix(level, "$") && !isWild(level) }

// MatchTopic reports whether a topic name matches a topic filter. Both must be valid. A filter
// whose first level is a wildcard never matches a topic name beginning with "$" (MQTT 5.0 section
// 4.7.2). "sport/#" also matches "sport" (section 4.7.1.2).
func MatchTopic(filter, name string) bool {
	f := strings.Split(filter, "/")
	t := strings.Split(name, "/")
	if strings.HasPrefix(name, "$") && isWild(f[0]) {
		return false
	}
	for i, fl := range f {
		if fl == "#" {
			return true
		}
		if i >= len(t) {
			return false
		}
		if fl != "+" && fl != t[i] {
			return false
		}
	}
	return len(f) == len(t)
}

// FilterCovers reports whether every topic name matching req also matches grant, that is whether
// a grant on the filter "grant" allows subscribing with the filter "req". Both must be valid and
// without a shared subscription prefix.
func FilterCovers(grant, req string) bool {
	g := strings.Split(grant, "/")
	r := strings.Split(req, "/")
	for i := 0; ; i++ {
		if i < len(g) && g[i] == "#" {
			return !(i == 0 && dollarLiteral(r[0]))
		}
		if i >= len(r) {
			return i >= len(g)
		}
		if i >= len(g) || r[i] == "#" {
			return false
		}
		if g[i] == "+" {
			if i == 0 && dollarLiteral(r[0]) {
				return false
			}
			continue
		}
		if r[i] != g[i] {
			return false
		}
	}
}

// FiltersOverlap reports whether some topic name matches both filters. It is used to apply deny
// rules to wildcard subscriptions conservatively: a deny rule on "secret/#" must block the
// subscription "#".
func FiltersOverlap(a, b string) bool {
	x := strings.Split(a, "/")
	y := strings.Split(b, "/")
	for i := 0; ; i++ {
		xh := i < len(x) && x[i] == "#"
		yh := i < len(y) && y[i] == "#"
		if xh || yh {
			if i == 0 {
				if xh && dollarLiteral(y[0]) || yh && dollarLiteral(x[0]) {
					return false
				}
			}
			return true
		}
		if i >= len(x) || i >= len(y) {
			return i >= len(x) && i >= len(y)
		}
		if x[i] != "+" && y[i] != "+" && x[i] != y[i] {
			return false
		}
		if i == 0 && (x[0] == "+" && dollarLiteral(y[0]) || y[0] == "+" && dollarLiteral(x[0])) {
			return false
		}
	}
}
