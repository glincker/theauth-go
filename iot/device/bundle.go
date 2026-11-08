package device

import (
	"errors"
	"math"
	"time"

	"github.com/glincker/theauth-go/v2/policy/pathmatch"
)

// BundleTyp is the `typ` header of an offline policy bundle (design D7).
const BundleTyp = "device-policy+jwt"

// DefaultIssuer is the `iss` the server uses unless `devices.issuer` is set.
const DefaultIssuer = "theauth"

// TimeWindow is a daily window in "HH:MM". Start after End means it crosses midnight.
type TimeWindow struct{ Start, End string }

// Constraints narrow one permission. The zero value constrains nothing.
type Constraints struct {
	// MaxCallsPerHour is nil when absent.
	MaxCallsPerHour *float64
	// AllowedArgPatterns are regular expressions every string argument must match.
	// They are compiled with Go's RE2 syntax; a pattern RE2 cannot compile denies.
	AllowedArgPatterns []string
	RequireApproval    bool
	TimeWindow         *TimeWindow
	IPAllowlist        []string
	// Attestation, when set, needs the bundle's attested device facts to meet the rule. A bundle
	// with no (or malformed) facts denies.
	Attestation *AttestationConstraint
}

// Permission grants Actions on resources matching Resource. Matching follows
// Claims.ResourceMatching: by default colon segments, a `*` segment matches the rest and a lone
// `*` matches everything; in path mode see package pathmatch.
type Permission struct {
	Resource    string
	Actions     []string
	Constraints *Constraints
}

// Claims is the payload of a policy bundle.
type Claims struct {
	Issuer, Subject, Audience string
	IssuedAt, NotBefore, Exp  int64
	JTI                       string
	// Seq is the issue time in milliseconds. Keep the highest one you accepted and pass
	// it as VerifyOptions.LastSeq, or an attacker can replay an older, wider bundle.
	Seq    int64
	Owner  string
	Groups []string
	Perms  []Permission
	// ResourceMatching is the signed "rm" claim: pathmatch.Path when the server matches resources
	// with resourceMatching "path", else pathmatch.Colon. Evaluate follows it, so the device
	// decides the way the server did when it issued the bundle.
	ResourceMatching pathmatch.Mode
	// Attestation is the signed "att" claim: the verified attestation facts of this device, or nil
	// when it enrolled without hardware evidence. Permissions with an attestation constraint need it.
	Attestation *AttestationFacts
}

// Reason says why VerifyBundle refused a token. The values match the TS verifyDeviceBundle.
type Reason string

const (
	ReasonInvalid     Reason = "invalid"
	ReasonWrongDevice Reason = "wrong_device"
	ReasonRollback    Reason = "rollback"
	// ReasonRevoked: the device is on a verified revocation snapshot.
	ReasonRevoked Reason = "revoked"
	// ReasonStaleRevocations: a device that opted in to offline revocation checks has no
	// snapshot, or it is expired or older than the allowed age. Fail closed.
	ReasonStaleRevocations Reason = "stale_revocations"
)

// VerifyError is returned by VerifyBundle.
type VerifyError struct {
	Reason  Reason
	Message string
}

func (e *VerifyError) Error() string { return "device: bundle " + string(e.Reason) + ": " + e.Message }

// VerifyOptions configures VerifyBundle.
type VerifyOptions struct {
	// Keys are the server's bundle verification keys (GET /device/jwks). Required.
	Keys *KeySet
	// DeviceID must equal the bundle's sub and aud. Required.
	DeviceID string
	// Issuer defaults to "theauth".
	Issuer string
	// LastSeq is the highest seq this device accepted before, 0 for none.
	LastSeq int64
	// Revocations opts in to offline revocation. Token is the snapshot delivered next to the
	// bundle. VerifyBundle then refuses a bundle with ReasonRevoked when this device is on the
	// list and with ReasonStaleRevocations when the snapshot is missing, expired or older than
	// MaxAge. Leave nil to skip the check. Owner is taken from the bundle.
	Revocations *RevocationOptions
	// Now is the current time. A device without a real time source should pass the
	// estimate from SyncedClock and refuse to verify before it has one.
	Now time.Time
}

// VerifyBundle checks signature, typ, iss, nbf and exp (30 s skew), that sub and aud are
// this device, and that seq did not go backwards. It matches TS verifyDeviceBundle, with
// one stricter rule: exp must be present, so a bundle can never be valid forever.
func VerifyBundle(token string, o VerifyOptions) (*Claims, error) {
	invalid := func(msg string) error { return &VerifyError{ReasonInvalid, msg} }
	t, err := parseJWS(token)
	if err != nil {
		return nil, invalid("malformed token")
	}
	alg, _ := t.header["alg"].(string)
	kid, _ := t.header["kid"].(string)
	key, found := o.Keys.Lookup(kid)
	if !typMatches(t.header["typ"], BundleTyp) || (alg != string(AlgES256) && alg != string(AlgEdDSA)) ||
		!found || alg != string(key.Alg) || !key.verifySig(t.input, t.sig) {
		return nil, invalid("signature, issuer or lifetime is invalid")
	}
	pv, err := parseJSON(t.payload)
	obj, isObj := pv.(map[string]any)
	if err != nil || !isObj {
		return nil, invalid("payload is not a JSON object")
	}
	issuer := o.Issuer
	if issuer == "" {
		issuer = DefaultIssuer
	}
	nowSec := o.Now.Unix()
	exp, hasExp := obj["exp"].(float64)
	nbf, hasNbf := obj["nbf"].(float64)
	if obj["iss"] != issuer || !hasExp || int64(exp) <= nowSec-skewSeconds ||
		(hasNbf && int64(nbf) > nowSec+skewSeconds) || (obj["nbf"] != nil && !hasNbf) {
		return nil, invalid("signature, issuer or lifetime is invalid")
	}
	if obj["sub"] != o.DeviceID || obj["aud"] != o.DeviceID {
		return nil, &VerifyError{ReasonWrongDevice, "issued for another device"}
	}
	seq, okSeq := obj["seq"].(float64)
	perms, okPerms := obj["perms"].([]any)
	if !okSeq || !okPerms {
		return nil, invalid("missing seq or perms")
	}
	if o.LastSeq != 0 && int64(seq) < o.LastSeq {
		return nil, &VerifyError{ReasonRollback, "older than the last bundle accepted"}
	}
	c := &Claims{Issuer: issuer, Subject: o.DeviceID, Audience: o.DeviceID, Exp: int64(exp), Seq: int64(seq), NotBefore: int64(nbf)}
	c.IssuedAt = int64(numOr(obj["iat"]))
	c.JTI, _ = obj["jti"].(string)
	c.Owner, _ = obj["owner"].(string)
	rm, _ := obj["rm"].(string)
	c.ResourceMatching = pathmatch.Resolve(rm)
	c.Attestation = parseFacts(obj["att"])
	if gs, ok := obj["groups"].([]any); ok {
		c.Groups = stringList(gs)
	}
	for _, pv := range perms {
		if p, ok := parsePermission(pv); ok {
			c.Perms = append(c.Perms, p)
		}
	}
	if o.Revocations != nil {
		ro := *o.Revocations
		ro.Owner = c.Owner
		snap, err := VerifyRevocations(ro, o.Keys, issuer, o.Now)
		if err != nil {
			return nil, err
		}
		if snap.Contains(o.DeviceID) {
			return nil, &VerifyError{ReasonRevoked, "device is on the revocation list"}
		}
	}
	return c, nil
}

var (
	errBundleAlg   = errors.New("device: bundles are signed with ES256 or EdDSA")
	errKidRequired = errors.New("device: kid is required")
)

func numOr(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

func stringList(in []any) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// parsePermission drops a malformed entry instead of guessing: a permission that cannot
// be read grants nothing, which fails closed.
func parsePermission(v any) (Permission, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return Permission{}, false
	}
	res, ok1 := m["resource"].(string)
	acts, ok2 := m["actions"].([]any)
	if !ok1 || !ok2 {
		return Permission{}, false
	}
	p := Permission{Resource: res, Actions: stringList(acts)}
	if cv, present := m["constraints"]; present && cv != nil {
		cm, ok := cv.(map[string]any)
		if !ok {
			return Permission{}, false
		}
		p.Constraints = parseConstraints(cm)
	}
	return p, true
}

func parseConstraints(m map[string]any) *Constraints {
	c := &Constraints{RequireApproval: truthy(m["requireApproval"])}
	if f, ok := m["maxCallsPerHour"].(float64); ok {
		c.MaxCallsPerHour = &f
	}
	if l, ok := m["allowedArgPatterns"].([]any); ok {
		c.AllowedArgPatterns = stringList(l)
	}
	if tw, ok := m["timeWindow"].(map[string]any); ok {
		w := &TimeWindow{}
		w.Start, _ = tw["start"].(string)
		w.End, _ = tw["end"].(string)
		c.TimeWindow = w
	}
	if l, ok := m["ipAllowlist"].([]any); ok {
		c.IPAllowlist = stringList(l)
	}
	// JavaScript truthiness, like requireApproval: the server ignores a rule only when it is falsy.
	if av, present := m["attestation"]; present && truthy(av) {
		c.Attestation = parseAttestationConstraint(av)
	}
	return c
}

// truthy follows JavaScript truthiness so `requireApproval: 1` or "yes" still denies,
// exactly as the TS evaluator does.
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0 && !math.IsNaN(t)
	case string:
		return t != ""
	case []any, map[string]any:
		return true
	}
	return false
}

// Map renders the claims as the JSON object the server signs.
func (c *Claims) Map() map[string]any {
	perms := make([]any, 0, len(c.Perms))
	for _, p := range c.Perms {
		pm := map[string]any{"resource": p.Resource, "actions": nonNil(p.Actions)}
		if k := p.Constraints; k != nil {
			km := map[string]any{}
			if k.MaxCallsPerHour != nil {
				km["maxCallsPerHour"] = *k.MaxCallsPerHour
			}
			if k.AllowedArgPatterns != nil {
				km["allowedArgPatterns"] = k.AllowedArgPatterns
			}
			if k.RequireApproval {
				km["requireApproval"] = true
			}
			if k.TimeWindow != nil {
				km["timeWindow"] = map[string]any{"start": k.TimeWindow.Start, "end": k.TimeWindow.End}
			}
			if k.IPAllowlist != nil {
				km["ipAllowlist"] = k.IPAllowlist
			}
			if k.Attestation != nil {
				km["attestation"] = k.Attestation.toMap()
			}
			pm["constraints"] = km
		}
		perms = append(perms, pm)
	}
	m := map[string]any{
		"iss": c.Issuer, "sub": c.Subject, "aud": c.Audience, "iat": c.IssuedAt, "nbf": c.NotBefore,
		"exp": c.Exp, "jti": c.JTI, "seq": c.Seq, "owner": c.Owner, "groups": nonNil(c.Groups), "perms": perms,
	}
	if c.ResourceMatching == pathmatch.Path {
		m["rm"] = string(pathmatch.Path)
	}
	if c.Attestation != nil {
		m["att"] = c.Attestation.Map()
	}
	return m
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// SignBundle signs claims as a policy bundle. The server (TS core) is the real issuer;
// this exists for Go gateways that act as a local issuer, and for tests. Only ES256 and
// EdDSA keys are valid, as on the server.
func (s *Signer) SignBundle(kid string, c Claims) (string, error) {
	if s.pub.Alg == AlgES384 {
		return "", errBundleAlg
	}
	if kid == "" {
		return "", errKidRequired
	}
	return signJWS(s, map[string]any{"alg": string(s.pub.Alg), "typ": BundleTyp, "kid": kid}, c.Map())
}
