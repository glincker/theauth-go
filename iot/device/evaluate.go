package device

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/policy/pathmatch"
)

// Decision codes. They are the same strings the TS DECISION_CODES use, so logs and
// audit uploads line up across the two implementations.
const (
	CodeAllowed          = "allowed"
	CodeNoPermission     = "no_permission"
	CodeRateLimited      = "rate_limited"
	CodeIPNotAllowed     = "ip_not_allowed"
	CodeTimeRestricted   = "time_restricted"
	CodeArgumentRejected = "argument_rejected"
	CodeApprovalRequired = "approval_required"
	// CodeAttestationRequired means the permission needs a hardware attested device and the
	// bundle's attestation facts are missing or too weak.
	CodeAttestationRequired = "attestation_required"
	CodeDeviceExpired       = "device_expired"
)

// Decision is the offline answer. Allowed is true only for CodeAllowed.
type Decision struct {
	Allowed bool
	Code    string
	Reason  string
}

type evalConfig struct {
	args  map[string]any
	ip    string
	calls int
	hasN  bool
	now   time.Time
	loc   *time.Location
}

// Option adjusts one Evaluate call.
type Option func(*evalConfig)

// WithArguments supplies the call arguments for allowedArgPatterns. As on the server,
// a permission with patterns and no arguments passed does not check any.
func WithArguments(args map[string]any) Option { return func(c *evalConfig) { c.args = args } }

// WithIP supplies the caller address for ipAllowlist.
func WithIP(ip string) Option { return func(c *evalConfig) { c.ip = ip } }

// WithCallsInLastHour supplies the device's own count of calls to this resource in the
// last hour. Without it a maxCallsPerHour permission denies (nothing to compare).
func WithCallsInLastHour(n int) Option {
	return func(c *evalConfig) { c.calls, c.hasN = n, true }
}

// WithNow sets the evaluation time. Default time.Now().
func WithNow(t time.Time) Option { return func(c *evalConfig) { c.now = t } }

// WithLocation sets the zone a timeWindow is read in. The bundle carries no zone and the
// server evaluates windows in its own local time, so use the server's zone. Default UTC.
func WithLocation(l *time.Location) Option { return func(c *evalConfig) { c.loc = l } }

// Evaluate decides whether the bundle grants action on resource, offline. It follows TS
// evaluateDeviceBundle rule for rule: the first permission whose resource and action
// match decides; requireApproval always denies (no human is reachable); a rate limited
// permission needs a local call count. Constraints run in the server order: rate,
// argument patterns, attestation, approval, time window, IP allowlist. Callers must have passed the
// claims through VerifyBundle.
func Evaluate(c *Claims, action, resource string, opts ...Option) Decision {
	cfg := evalConfig{loc: time.UTC}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.now.IsZero() {
		cfg.now = time.Now()
	}
	if cfg.now.UnixMilli() > (c.Exp+skewSeconds)*1000 {
		return Decision{false, CodeDeviceExpired, "Bundle has expired"}
	}
	var perm *Permission
	for i := range c.Perms {
		if pathmatch.Match(c.ResourceMatching, c.Perms[i].Resource, resource) && matchAction(c.Perms[i].Actions, action) {
			perm = &c.Perms[i]
			break
		}
	}
	if perm == nil {
		return Decision{false, CodeNoPermission, `Bundle grants no "` + action + `" on "` + resource + `"`}
	}
	k := perm.Constraints
	if k == nil {
		return Decision{true, CodeAllowed, ""}
	}
	if k.RequireApproval {
		return Decision{false, CodeApprovalRequired, "Approval needs the server; denied offline"}
	}
	if k.MaxCallsPerHour != nil && !cfg.hasN {
		return Decision{false, CodeRateLimited, "Rate limited permission needs a local call count offline"}
	}
	if k.MaxCallsPerHour != nil && float64(cfg.calls) >= *k.MaxCallsPerHour {
		return Decision{false, CodeRateLimited, "Rate limit exceeded: " + strconv.Itoa(cfg.calls) + "/" + strconv.FormatFloat(*k.MaxCallsPerHour, 'f', -1, 64) + " calls per hour for resource \"" + resource + `"`}
	}
	if k.AllowedArgPatterns != nil && cfg.args != nil {
		if reason, ok := checkArgPatterns(k.AllowedArgPatterns, cfg.args); !ok {
			return Decision{false, CodeArgumentRejected, reason}
		}
	}
	if k.Attestation != nil {
		if reason := k.Attestation.check(c.Attestation); reason != "" {
			return Decision{false, CodeAttestationRequired, reason}
		}
	}
	if k.TimeWindow != nil && !inTimeWindow(k.TimeWindow, cfg.now.In(cfg.loc)) {
		return Decision{false, CodeTimeRestricted, "Action is only allowed between " + k.TimeWindow.Start + " and " + k.TimeWindow.End}
	}
	if len(k.IPAllowlist) > 0 {
		if cfg.ip == "" {
			return Decision{false, CodeIPNotAllowed, "IP_NOT_ALLOWED: No IP address provided; resource requires an IP allowlist match"}
		}
		if !ipAllowed(k.IPAllowlist, cfg.ip) {
			return Decision{false, CodeIPNotAllowed, `IP_NOT_ALLOWED: IP "` + cfg.ip + `" is not in the allowlist for this resource`}
		}
	}
	return Decision{true, CodeAllowed, ""}
}

func matchAction(allowed []string, action string) bool {
	return slices.Contains(allowed, action) || slices.Contains(allowed, "*")
}

// parseClock reads "HH:MM" into minutes of the day, -1 when malformed.
func parseClock(s string) int {
	if len(s) != 5 || s[2] != ':' {
		return -1
	}
	d := func(i int) int { return int(s[i] - '0') }
	for _, i := range [...]int{0, 1, 3, 4} {
		if s[i] < '0' || s[i] > '9' {
			return -1
		}
	}
	h, m := d(0)*10+d(1), d(3)*10+d(4)
	if h > 23 || m > 59 {
		return -1
	}
	return h*60 + m
}

// inTimeWindow has inclusive edges. Start after End is an overnight window.
func inTimeWindow(w *TimeWindow, now time.Time) bool {
	start, end := parseClock(w.Start), parseClock(w.End)
	if start < 0 || end < 0 {
		return false
	}
	n := now.Hour()*60 + now.Minute()
	if start <= end {
		return n >= start && n <= end
	}
	return n >= start || n <= end
}

func ipAllowed(list []string, ip string) bool {
	for _, entry := range list {
		if ipMatchesEntry(entry, ip) {
			return true
		}
	}
	return false
}

// ipMatchesEntry matches an exact string or an IPv4 CIDR, like the server. IPv6 works
// only as an exact string match.
func ipMatchesEntry(entry, ip string) bool {
	cidr, bits, hasSlash := strings.Cut(entry, "/")
	if !hasSlash {
		return entry == ip
	}
	n, ok := parseIntPrefix(bits)
	if !ok || n < 0 || n > 32 {
		return false
	}
	a, ok1 := parseIPv4(cidr)
	b, ok2 := parseIPv4(ip)
	if !ok1 || !ok2 {
		return false
	}
	var mask uint32
	if n > 0 {
		mask = ^uint32(0) << (32 - uint(n))
	}
	return a&mask == b&mask
}

// parseIntPrefix mimics JavaScript parseInt(s, 10): optional leading space and sign,
// then the longest run of digits, anything after is ignored.
func parseIntPrefix(s string) (int, bool) {
	s = strings.TrimLeft(s, " \t\n\r")
	i, neg := 0, false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == start || i-start > 9 {
		return 0, false
	}
	n, _ := strconv.Atoi(s[start:i])
	if neg {
		n = -n
	}
	return n, true
}

func parseIPv4(s string) (uint32, bool) {
	// The server accepts only four dotted decimal parts of one to three digits, each at
	// most 255. Leading zeros read as decimal ("010" is 10).
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0, false
	}
	var out uint32
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return 0, false
		}
		n := 0
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return 0, false
			}
			n = n*10 + int(p[i]-'0')
		}
		if n > 255 {
			return 0, false
		}
		out = out<<8 | uint32(n)
	}
	return out, true
}

const maxArgDepth = 32

type compiled struct {
	src string
	re  *regexp.Regexp
}

func checkArgPatterns(patterns []string, args map[string]any) (string, bool) {
	res := make([]compiled, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return `Invalid argument pattern "` + p + `"`, false
		}
		res = append(res, compiled{p, re})
	}
	return walkArgs(res, args, "", 0)
}

func walkArgs(res []compiled, v any, path string, depth int) (string, bool) {
	switch t := v.(type) {
	case string:
		for _, c := range res {
			if !c.re.MatchString(t) {
				return `Argument "` + path + `" value "` + t + `" does not match pattern "` + c.src + `"`, false
			}
		}
	case []any:
		if depth >= maxArgDepth {
			return `Argument "` + path + `" is nested too deeply to validate`, false
		}
		for i, e := range t {
			if r, ok := walkArgs(res, e, path+"["+strconv.Itoa(i)+"]", depth+1); !ok {
				return r, false
			}
		}
	case map[string]any:
		if depth >= maxArgDepth {
			return `Argument "` + path + `" is nested too deeply to validate`, false
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			child := k
			if path != "" {
				child = path + "." + k
			}
			if r, ok := walkArgs(res, t[k], child, depth+1); !ok {
				return r, false
			}
		}
	}
	return "", true
}
