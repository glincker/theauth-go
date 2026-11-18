package visitorsignal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"unicode/utf8"
)

var (
	nonceRe        = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	screenBucketRe = regexp.MustCompile(`^[1-9][0-9]{0,2}00x[1-9][0-9]{0,2}00@[0-9](\.[0-9])?$`)
	renderHashRe   = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

func keySet(keys ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		m[k] = struct{}{}
	}
	return m
}

var (
	topKeys = keySet("v", "mode", "status", "suppressedReason", "ts", "nonce",
		"challenge", "components", "unavailable", "flags", "collectMs")
	topRequired = []string{"v", "mode", "ts", "nonce", "status", "components", "flags"}

	componentKeys = keySet("tz", "tzOffsetMin", "lang", "langCount", "platform",
		"uaBrand", "uaMajor", "mobile", "screenBucket", "colorDepth", "touchPoints",
		"cores", "memoryGb", "reducedMotion", "colorScheme", "caps", "renderHash")

	flagKeys = keySet("protectedBrowser", "webdriver", "headlessHint", "inconsistent",
		"automationGlobals", "noInputObserved", "dnt", "gpc")
	flagRequired = []string{"protectedBrowser", "webdriver", "headlessHint", "inconsistent"}

	unavailableEnum = keySet("tz", "lang", "platform", "ua", "screen", "touch",
		"cores", "memory", "caps", "renderHash")
)

// ValidatePayload validates raw against schema v1 using DefaultConfig limits.
func ValidatePayload(raw []byte) (Payload, error) {
	return ValidatePayloadWithConfig(raw, DefaultConfig())
}

// ValidatePayloadWithConfig validates raw against schema v1. An unsupported
// version is reported before any other schema rule. Integer fields must be
// written without a fraction or exponent, which is stricter than JSON Schema
// and matches what the collector emits.
func ValidatePayloadWithConfig(raw []byte, cfg Config) (Payload, error) {
	var zero Payload
	if err := cfg.Validate(); err != nil {
		return zero, err
	}
	if int64(len(raw)) > cfg.MaxBodyBytes {
		return zero, newError(CodeSchemaInvalid, "body exceeds size cap")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return zero, newError(CodeSchemaInvalid, "body is not a JSON object")
	}
	if err := checkVersion(top); err != nil {
		return zero, err
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return zero, err
	}
	if err := checkKeys(top, topKeys, topRequired, "payload"); err != nil {
		return zero, err
	}
	comps, err := objectKeys(top["components"], componentKeys, nil, "components")
	if err != nil {
		return zero, err
	}
	if _, err := objectKeys(top["flags"], flagKeys, flagRequired, "flags"); err != nil {
		return zero, err
	}
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return zero, newError(CodeSchemaInvalid, "field has the wrong type")
	}
	_, hasReason := top["suppressedReason"]
	if err := checkSemantics(p, hasReason, comps); err != nil {
		return zero, err
	}
	return p, nil
}

// maxJSONDepth bounds the pre-pass recursion. The schema nests three deep.
const maxJSONDepth = 16

// rejectDuplicateKeys walks the token stream and refuses any object that
// repeats a key. Without it the map and struct decoders each keep the last
// value, so a first copy could carry data that the later checks never see.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := walkTokens(dec, 0); err != nil {
		return err
	}
	return nil
}

func walkTokens(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return newError(CodeSchemaInvalid, "body is nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return newError(CodeSchemaInvalid, "body is not valid JSON")
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return newError(CodeSchemaInvalid, "body is not valid JSON")
			}
			key, _ := kt.(string)
			if _, dup := seen[key]; dup {
				return newError(CodeSchemaInvalid, "duplicate key in body")
			}
			seen[key] = struct{}{}
			if err := walkTokens(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkTokens(dec, depth+1); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return newError(CodeSchemaInvalid, "body is not valid JSON")
	}
	return nil
}

func checkVersion(top map[string]json.RawMessage) error {
	rawV, ok := top["v"]
	if !ok {
		return newError(CodeSchemaInvalid, "v is required")
	}
	var n json.Number
	if err := json.Unmarshal(rawV, &n); err != nil {
		return newError(CodeSchemaInvalid, "v must be a number")
	}
	if f, err := n.Float64(); err != nil || f != SchemaVersion {
		return newError(CodeUnsupportedVersion, "v is not supported")
	}
	if string(bytes.TrimSpace(rawV)) != "1" {
		return newError(CodeSchemaInvalid, "v must be written as 1")
	}
	return nil
}

// checkKeys enforces the closed object rule, required keys and no nulls.
func checkKeys(m map[string]json.RawMessage, allowed map[string]struct{}, required []string, where string) error {
	for k, v := range m {
		if _, ok := allowed[k]; !ok {
			return newError(CodeSchemaInvalid, fmt.Sprintf("unknown field in %s", where))
		}
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return newError(CodeSchemaInvalid, fmt.Sprintf("null is not allowed in %s", where))
		}
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return newError(CodeSchemaInvalid, fmt.Sprintf("%s is missing %s", where, k))
		}
	}
	return nil
}

func objectKeys(raw json.RawMessage, allowed map[string]struct{}, required []string, where string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, newError(CodeSchemaInvalid, where+" must be an object")
	}
	if err := checkKeys(m, allowed, required, where); err != nil {
		return nil, err
	}
	return m, nil
}

func checkSemantics(p Payload, hasReason bool, comps map[string]json.RawMessage) error {
	bad := func(msg string) error { return newError(CodeSchemaInvalid, msg) }
	if !p.Mode.Valid() {
		return bad("mode is not allowed")
	}
	switch p.Status {
	case StatusOK, StatusPartial, StatusSuppressed:
	default:
		return bad("status is not allowed")
	}
	if p.TS < 0 {
		return bad("ts must not be negative")
	}
	if n := len(p.Nonce); n < 16 || n > 64 || !nonceRe.MatchString(p.Nonce) {
		return bad("nonce is malformed")
	}
	if utf8.RuneCountInString(p.Challenge) > 2048 {
		return bad("challenge is too long")
	}
	if p.CollectMs < 0 || p.CollectMs > 60000 {
		return bad("collectMs is out of range")
	}
	if err := checkSuppression(p, hasReason, comps); err != nil {
		return err
	}
	if p.Mode == ModeAnalytics && p.Status != StatusSuppressed && (p.Flags.DNT || p.Flags.GPC) {
		return bad("analytics payload must be suppressed when dnt or gpc is set")
	}
	if err := checkComponents(p.Components, p.Mode); err != nil {
		return err
	}
	if err := checkFlags(p.Flags); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(p.Unavailable))
	for _, u := range p.Unavailable {
		if _, ok := unavailableEnum[u]; !ok {
			return bad("unavailable entry is not allowed")
		}
		if _, dup := seen[u]; dup {
			return bad("unavailable entries must be unique")
		}
		seen[u] = struct{}{}
	}
	return nil
}

func checkSuppression(p Payload, hasReason bool, comps map[string]json.RawMessage) error {
	bad := func(msg string) error { return newError(CodeSchemaInvalid, msg) }
	if p.Status != StatusSuppressed {
		if hasReason {
			return bad("suppressedReason is only allowed when suppressed")
		}
		return nil
	}
	switch p.SuppressedReason {
	case ReasonConsentDenied, ReasonConsentUnknown, ReasonDNT, ReasonGPC, ReasonRouteNotProtected:
	default:
		return bad("suppressed payload needs a valid suppressedReason")
	}
	if len(comps) != 0 {
		return bad("suppressed payload must carry no components")
	}
	return nil
}

func checkComponents(c Components, mode Mode) error {
	bad := func(msg string) error { return newError(CodeSchemaInvalid, "components: "+msg) }
	strMax := func(name string, v *string, max int) error {
		if v != nil && utf8.RuneCountInString(*v) > max {
			return bad(name + " is too long")
		}
		return nil
	}
	intRange := func(name string, v *int, lo, hi int) error {
		if v != nil && (*v < lo || *v > hi) {
			return bad(name + " is out of range")
		}
		return nil
	}
	for _, err := range []error{
		strMax("tz", c.TZ, 64), strMax("lang", c.Lang, 35),
		strMax("platform", c.Platform, 32), strMax("uaBrand", c.UABrand, 32),
		intRange("tzOffsetMin", c.TZOffsetMin, -840, 840),
		intRange("langCount", c.LangCount, 0, 20),
		intRange("uaMajor", c.UAMajor, 0, 999),
		intRange("touchPoints", c.TouchPoints, 0, 10),
	} {
		if err != nil {
			return err
		}
	}
	if c.ScreenBucket != nil && !screenBucketRe.MatchString(*c.ScreenBucket) {
		return bad("screenBucket is not bucketed")
	}
	if c.ColorDepth != nil && !oneOfInt(*c.ColorDepth, 16, 24, 30, 32, 48) {
		return bad("colorDepth is not allowed")
	}
	if c.Cores != nil && !oneOfInt(*c.Cores, 1, 2, 4, 8, 16, 32, 64) {
		return bad("cores is not a bucketed power of two")
	}
	if c.MemoryGB != nil && !oneOfFloat(*c.MemoryGB, 0.25, 0.5, 1, 2, 4, 8) {
		return bad("memoryGb is not allowed")
	}
	if c.ColorScheme != nil && *c.ColorScheme != "light" && *c.ColorScheme != "dark" && *c.ColorScheme != "none" {
		return bad("colorScheme is not allowed")
	}
	if c.RenderHash != nil {
		if mode == ModeAnalytics {
			return bad("renderHash is only allowed in fraud_prevention mode")
		}
		if !renderHashRe.MatchString(*c.RenderHash) {
			return bad("renderHash is malformed")
		}
	}
	return nil
}

func checkFlags(f Flags) error {
	if f.AutomationGlobals < 0 || f.AutomationGlobals > 32 {
		return newError(CodeSchemaInvalid, "flags: automationGlobals is out of range")
	}
	return nil
}

func oneOfInt(v int, allowed ...int) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func oneOfFloat(v float64, allowed ...float64) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}
