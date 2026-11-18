package visitorsignal

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// SignalV1MaxBytes is the body limit fixed by SPEC part 2.
const SignalV1MaxBytes = 512

// SignalV1 is the cookieless digest profile. It is advisory and must never
// gate a security decision.
type SignalV1 struct {
	V          int     `json:"v"`
	Source     string  `json:"source"`
	Digest     string  `json:"digest"`
	Confidence float64 `json:"confidence"`
	Components int     `json:"components"`
	TS         int64   `json:"ts"`
}

var signalV1Keys = []string{"v", "source", "digest", "confidence", "components", "ts"}

// ComputeSignalV1Digest returns base64url(SHA-256(pepper || 0x00 || concat(h_i)))
// without padding, where h_i = SHA-256(name || 0x00 || canonicalValue).
func ComputeSignalV1Digest(c Components, pepper string) (string, error) {
	entries, err := componentEntries(c)
	if err != nil {
		return "", err
	}
	outer := sha256.New()
	outer.Write([]byte(pepper))
	outer.Write([]byte{0})
	for _, e := range entries {
		h := sha256.New()
		h.Write([]byte(e.name))
		h.Write([]byte{0})
		h.Write([]byte(e.value))
		outer.Write(h.Sum(nil))
	}
	return base64.RawURLEncoding.EncodeToString(outer.Sum(nil)), nil
}

// ParseSignalV1 decodes a SignalV1 body strictly.
func ParseSignalV1(raw []byte) (SignalV1, error) {
	var zero SignalV1
	bad := func(msg string) (SignalV1, error) { return zero, newError(CodeSchemaInvalid, msg) }
	if len(raw) > SignalV1MaxBytes {
		return bad("body exceeds 512 bytes")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return bad("body is not a JSON object")
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return zero, err
	}
	allowed := keySet(signalV1Keys...)
	if err := checkKeys(top, allowed, signalV1Keys, "signal"); err != nil {
		return zero, err
	}
	var s SignalV1
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return bad("field has the wrong type")
	}
	if s.V != SchemaVersion {
		return zero, newError(CodeUnsupportedVersion, "v is not supported")
	}
	if s.Source != "browser" {
		return bad("source must be browser")
	}
	d, err := base64.RawURLEncoding.Strict().DecodeString(s.Digest)
	if err != nil || len(d) != sha256.Size {
		return bad("digest must be 32 bytes of unpadded base64url")
	}
	if !(s.Confidence >= 0 && s.Confidence <= 1) {
		return bad("confidence must be within [0,1]")
	}
	if s.Components < 0 || s.Components > len(componentNames) {
		return bad("components count is out of range")
	}
	if s.TS < 0 {
		return bad("ts must not be negative")
	}
	return s, nil
}

// componentNames lists every component the schema defines.
var componentNames = []string{"tz", "tzOffsetMin", "lang", "langCount", "platform",
	"uaBrand", "uaMajor", "mobile", "screenBucket", "colorDepth", "touchPoints",
	"cores", "memoryGb", "reducedMotion", "colorScheme", "caps", "renderHash"}
