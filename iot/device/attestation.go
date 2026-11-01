package device

import "slices"

// attestation.go is the offline half of the attestation policy condition. The server derives a
// small set of facts from the verified attestation claims of a device (see attest.FactsFromClaims)
// and signs them into the bundle as the "att" claim. A permission with an "attestation" constraint
// is then decided against those facts, with the same rules and the same refusal sentences as the
// TypeScript checkAttestationConstraint. Replayed from shared vectors in attestation_vectors_test.go.

// Security levels of an attested key, lowest first.
const (
	LevelSoftware  = "software"
	LevelHardware  = "hardware"
	LevelStrongbox = "strongbox"
)

// Boot states an attestation can report.
const (
	BootVerified   = "verified"
	BootSelfSigned = "self_signed"
	BootUnverified = "unverified"
	BootFailed     = "failed"
	BootUnlocked   = "unlocked"
)

// AttestationFacts is what policy reads from verified attestation claims.
type AttestationFacts struct {
	// Format is the verifier format claim, for example "android-key-attestation".
	Format string
	// SecurityLevel is LevelSoftware, LevelHardware or LevelStrongbox.
	SecurityLevel string
	// BootState is empty when the format carries no boot state.
	BootState string
	// AppIDs are the attested app identifiers (Android packages, Apple teamId.bundleId).
	AppIDs []string
}

// Map renders the facts as the JSON object signed into the bundle.
func (f AttestationFacts) Map() map[string]any {
	m := map[string]any{"format": f.Format, "securityLevel": f.SecurityLevel}
	if f.BootState != "" {
		m["bootState"] = f.BootState
	}
	if len(f.AppIDs) > 0 {
		m["appIds"] = f.AppIDs
	}
	return m
}

// AttestationConstraint is the rule on Constraints.Attestation. Every field that is set must hold.
type AttestationConstraint struct {
	// MinSecurityLevel is LevelSoftware, LevelHardware or LevelStrongbox when a minimum is set.
	// Any other value in a signed rule marks it malformed and denies.
	MinSecurityLevel string
	// hasLevel is set when the rule names a minimum level. A built rule sets it through SetMinLevel.
	hasLevel bool
	// BootState lists the accepted boot states. Nil means no rule, an empty list matches nothing.
	BootState []string
	// AppIDs lists the accepted app ids. Nil means no rule, an empty list matches nothing.
	AppIDs []string
	// malformed is set when the signed rule had a field of the wrong shape. It denies.
	malformed bool
}

var levelRank = map[string]int{LevelSoftware: 0, LevelHardware: 1, LevelStrongbox: 2}

var validBoot = []string{BootVerified, BootSelfSigned, BootUnverified, BootFailed, BootUnlocked}

// parseFacts narrows the untrusted "att" claim. It returns nil for anything not well formed, and a
// nil fact set makes every attestation constraint deny.
func parseFacts(v any) *AttestationFacts {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	format, _ := m["format"].(string)
	level, _ := m["securityLevel"].(string)
	if format == "" {
		return nil
	}
	if _, known := levelRank[level]; !known {
		return nil
	}
	f := &AttestationFacts{Format: format, SecurityLevel: level}
	if bs, _ := m["bootState"].(string); slices.Contains(validBoot, bs) {
		f.BootState = bs
	}
	if l, ok := m["appIds"].([]any); ok {
		for _, id := range stringList(l) {
			if id != "" {
				f.AppIDs = append(f.AppIDs, id)
			}
		}
	}
	return f
}

func parseAttestationConstraint(v any) *AttestationConstraint {
	c := &AttestationConstraint{}
	m, ok := v.(map[string]any)
	if !ok {
		// A truthy non object (true, 1, "x") is a rule with no fields: it needs facts and nothing more.
		return c
	}
	if lv, present := m["minSecurityLevel"]; present {
		c.hasLevel = true
		s, isStr := lv.(string)
		if _, known := levelRank[s]; !isStr || !known {
			c.malformed = true
		}
		c.MinSecurityLevel = s
	}
	if bv, present := m["bootState"]; present {
		l, isList := bv.([]any)
		if !isList {
			c.malformed = true
		}
		c.BootState = stringList(l)
	}
	if av, present := m["appIds"]; present {
		l, isList := av.([]any)
		if !isList {
			c.malformed = true
		}
		c.AppIDs = stringList(l)
	}
	return c
}

// NewAttestationConstraint builds a rule. minLevel is "" for none, else LevelHardware or
// LevelStrongbox. bootStates and appIDs are nil for no rule, an empty slice matches nothing.
func NewAttestationConstraint(minLevel string, bootStates, appIDs []string) *AttestationConstraint {
	c := &AttestationConstraint{BootState: bootStates, AppIDs: appIDs}
	if minLevel != "" {
		c.hasLevel, c.MinSecurityLevel = true, minLevel
		if _, known := levelRank[minLevel]; !known {
			c.malformed = true
		}
	}
	return c
}

func (c *AttestationConstraint) toMap() map[string]any {
	m := map[string]any{}
	if c.hasLevel {
		m["minSecurityLevel"] = c.MinSecurityLevel
	}
	if c.BootState != nil {
		m["bootState"] = c.BootState
	}
	if c.AppIDs != nil {
		m["appIds"] = c.AppIDs
	}
	return m
}

const attestationNeeded = "ATTESTATION_REQUIRED: "

// check returns the refusal sentence, or "" when the facts satisfy the rule. Nil facts fail closed.
func (c *AttestationConstraint) check(f *AttestationFacts) string {
	if f == nil {
		return attestationNeeded + "This action needs a hardware attested device"
	}
	if c.malformed {
		return attestationNeeded + "Attestation rule is malformed"
	}
	if c.hasLevel {
		if levelRank[f.SecurityLevel] < levelRank[c.MinSecurityLevel] {
			return attestationNeeded + `Device key security level "` + f.SecurityLevel + `" is below the required "` + c.MinSecurityLevel + `"`
		}
	}
	if c.BootState != nil {
		if f.BootState == "" {
			return attestationNeeded + "Device boot state is not attested"
		}
		if !slices.Contains(c.BootState, f.BootState) {
			return attestationNeeded + `Device boot state "` + f.BootState + `" is not accepted`
		}
	}
	if c.AppIDs != nil {
		ok := false
		for _, id := range f.AppIDs {
			if slices.Contains(c.AppIDs, id) {
				ok = true
			}
		}
		if !ok {
			return attestationNeeded + "Attested app is not an allowed app"
		}
	}
	return ""
}
