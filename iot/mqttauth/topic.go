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
	// One byte pass: a level is "#" (last level only), "+", or free of both wildcard characters.
	start, wild := 0, false
	for i := 0; i <= len(filter); i++ {
		if i < len(filter) && filter[i] != '/' {
			if c := filter[i]; c == '+' || c == '#' {
				wild = true
			}
			continue
		}
		switch l := filter[start:i]; {
		case l == "#":
			if i < len(filter) {
				return invalid("# must be the last level")
			}
		case l == "+":
		case wild:
			return invalid("wildcard must occupy a whole level")
		}
		start, wild = i+1, false
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

// cutLevel splits off the first topic level. more reports whether a "/" followed it, that is
// whether rest holds further levels (possibly one empty level). It lets the matchers walk a topic
// without allocating the slice strings.Split would.
func cutLevel(s string) (level, rest string, more bool) {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// MatchTopic reports whether a topic name matches a topic filter. Both must be valid. A filter
// whose first level is a wildcard never matches a topic name beginning with "$" (MQTT 5.0 section
// 4.7.2). "sport/#" also matches "sport" (section 4.7.1.2).
func MatchTopic(filter, name string) bool {
	fl, frest, fmore := cutLevel(filter)
	if strings.HasPrefix(name, "$") && isWild(fl) {
		return false
	}
	tl, trest, tmore := cutLevel(name)
	haveT := true
	for {
		if fl == "#" {
			return true
		}
		if !haveT {
			return false
		}
		if fl != "+" && fl != tl {
			return false
		}
		if !fmore {
			return !tmore
		}
		fl, frest, fmore = cutLevel(frest)
		if tmore {
			tl, trest, tmore = cutLevel(trest)
		} else {
			haveT = false
		}
	}
}

// FilterCovers reports whether every topic name matching req also matches grant, that is whether
// a grant on the filter "grant" allows subscribing with the filter "req". Both must be valid and
// without a shared subscription prefix.
func FilterCovers(grant, req string) bool {
	r0, _, _ := cutLevel(req)
	gl, grest, gmore := cutLevel(grant)
	rl, rrest, rmore := cutLevel(req)
	haveG, haveR := true, true
	for i := 0; ; i++ {
		if haveG && gl == "#" {
			return i != 0 || !dollarLiteral(r0)
		}
		if !haveR {
			return !haveG
		}
		if !haveG || rl == "#" {
			return false
		}
		if gl == "+" {
			if i == 0 && dollarLiteral(r0) {
				return false
			}
		} else if rl != gl {
			return false
		}
		if gmore {
			gl, grest, gmore = cutLevel(grest)
		} else {
			haveG = false
		}
		if rmore {
			rl, rrest, rmore = cutLevel(rrest)
		} else {
			haveR = false
		}
	}
}

// FiltersOverlap reports whether some topic name matches both filters. It is used to apply deny
// rules to wildcard subscriptions conservatively: a deny rule on "secret/#" must block the
// subscription "#".
func FiltersOverlap(a, b string) bool {
	x0, _, _ := cutLevel(a)
	y0, _, _ := cutLevel(b)
	xl, xrest, xmore := cutLevel(a)
	yl, yrest, ymore := cutLevel(b)
	haveX, haveY := true, true
	for i := 0; ; i++ {
		xh := haveX && xl == "#"
		yh := haveY && yl == "#"
		if xh || yh {
			if i == 0 && (xh && dollarLiteral(y0) || yh && dollarLiteral(x0)) {
				return false
			}
			return true
		}
		if !haveX || !haveY {
			return !haveX && !haveY
		}
		if xl != "+" && yl != "+" && xl != yl {
			return false
		}
		if i == 0 && (xl == "+" && dollarLiteral(y0) || yl == "+" && dollarLiteral(x0)) {
			return false
		}
		if xmore {
			xl, xrest, xmore = cutLevel(xrest)
		} else {
			haveX = false
		}
		if ymore {
			yl, yrest, ymore = cutLevel(yrest)
		} else {
			haveY = false
		}
	}
}
