package hook

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// Guard protocol 2026-10. Header names and limits match the TypeScript
// library's http-guard.ts byte for byte.
const (
	ProtocolVersion           = "2026-10"
	HeaderTimestamp           = "X-Theauth-Timestamp"
	HeaderSignature           = "X-Theauth-Signature"
	HeaderVersion             = "X-Theauth-Guard-Version"
	HeaderKeyID               = "X-Theauth-Key-Id"
	HeaderResponseTimestamp   = "X-Theauth-Response-Timestamp"
	HeaderResponseSignature   = "X-Theauth-Response-Signature"
	DefaultTolerance          = 300 * time.Second
	MaxBodyBytes              = 64 << 10
	maxRequestIDLen           = 128
	maxReasonUnits            = 1024
	maxShortUnits             = 128
	signaturePrefix           = "v1="
	issuedAtLayout            = "2006-01-02T15:04:05.000Z"
	errReasonBadSignature     = "bad signature"
	errReasonBadRespSignature = "bad response signature"
)

// Verification failures. Each error from VerifyGuardRequest and
// VerifyGuardResponse wraps one of these; the text matches the TypeScript
// reason strings.
var (
	ErrMissingSignature = errors.New("missing signature headers")
	ErrBadTimestamp     = errors.New("bad timestamp")
	ErrStaleTimestamp   = errors.New("stale timestamp")
	ErrBadSignature     = errors.New(errReasonBadSignature)
	ErrMalformedRequest = errors.New("malformed envelope")
	ErrReplayedRequest  = errors.New("replayed request")
	ErrBodyTooLarge     = errors.New("guard body too large")
)

var timestampPattern = regexp.MustCompile(`^[0-9]{1,12}$`)

func hmacHex(secret, message []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(message)
	return hex.EncodeToString(m.Sum(nil))
}

// SignGuardBody returns the request signature header value:
// v1=hex(HMAC-SHA256(secret, "<timestamp>.<body>")).
func SignGuardBody(secret string, timestamp int64, body []byte) string {
	msg := make([]byte, 0, len(body)+21)
	msg = strconv.AppendInt(msg, timestamp, 10)
	msg = append(msg, '.')
	msg = append(msg, body...)
	return signaturePrefix + hmacHex([]byte(secret), msg)
}

// SignGuardResponseBody returns the response signature header value:
// v1=hex(HMAC-SHA256(secret, "<requestId>.<timestamp>.<body>")).
func SignGuardResponseBody(secret, requestID string, timestamp int64, body []byte) string {
	msg := make([]byte, 0, len(requestID)+len(body)+22)
	msg = append(msg, requestID...)
	msg = append(msg, '.')
	msg = strconv.AppendInt(msg, timestamp, 10)
	msg = append(msg, '.')
	msg = append(msg, body...)
	return signaturePrefix + hmacHex([]byte(secret), msg)
}

// SignGuardResponse is the vendor side signer. It returns the two response
// headers for body, bound to requestID. A zero timestamp means now. Sign the
// exact bytes you send.
func SignGuardResponse(secret, requestID string, body []byte, timestamp int64) http.Header {
	if timestamp == 0 {
		timestamp = time.Now().Unix()
	}
	h := http.Header{}
	h.Set(HeaderResponseTimestamp, strconv.FormatInt(timestamp, 10))
	h.Set(HeaderResponseSignature, SignGuardResponseBody(secret, requestID, timestamp, body))
	return h
}

// signatureEqual compares two signature strings in constant time.
func signatureEqual(expected, given string) bool {
	return hmac.Equal([]byte(expected), []byte(given))
}

// VerifyOptions tunes VerifyGuardRequest and VerifyGuardResponse.
type VerifyOptions struct {
	// Tolerance is the max age or clock skew. Zero means DefaultTolerance.
	Tolerance time.Duration
	// Seen reports whether this request id was already accepted, so a vendor
	// can refuse exact replays inside the window. Request side only.
	Seen func(requestID string) bool
	// Now is the clock. Nil uses time.Now.
	Now func() time.Time
}

func (o *VerifyOptions) tolerance() int64 {
	if o == nil || o.Tolerance <= 0 {
		return int64(DefaultTolerance / time.Second)
	}
	return int64(o.Tolerance / time.Second)
}

func (o *VerifyOptions) now() int64 {
	if o == nil || o.Now == nil {
		return time.Now().Unix()
	}
	return o.Now().Unix()
}

// checkFreshness parses a timestamp header and applies the window.
func checkFreshness(raw string, opts *VerifyOptions, stale error) (int64, error) {
	if !timestampPattern.MatchString(raw) {
		return 0, ErrBadTimestamp
	}
	ts, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, ErrBadTimestamp
	}
	d := opts.now() - ts
	if d < 0 {
		d = -d
	}
	if d > opts.tolerance() {
		return 0, stale
	}
	return ts, nil
}

// GuardRequest is a verified request envelope.
type GuardRequest struct {
	Version   string `json:"version"`
	RequestID string `json:"requestId"`
	IssuedAt  string `json:"issuedAt"`
	Input     Input  `json:"input"`
}

// VerifyGuardRequest is the vendor side check: header presence, timestamp
// freshness, then the HMAC over the raw body in constant time, then the
// envelope. body must be the raw request bytes, not re-encoded JSON. Unknown
// envelope fields are accepted, as in the TypeScript verifier, so newer
// clients keep working.
//
//	req, err := hook.VerifyGuardRequest(secret, r.Header, body, nil)
//	if err != nil { w.WriteHeader(http.StatusUnauthorized); return }
//	_ = hook.WriteGuardResponse(w, secret, req.RequestID, decide(req.Input))
func VerifyGuardRequest(secret string, header http.Header, body []byte, opts *VerifyOptions) (*GuardRequest, error) {
	tsRaw, sig := header.Get(HeaderTimestamp), header.Get(HeaderSignature)
	if tsRaw == "" || sig == "" {
		return nil, ErrMissingSignature
	}
	ts, err := checkFreshness(tsRaw, opts, ErrStaleTimestamp)
	if err != nil {
		return nil, err
	}
	if !signatureEqual(SignGuardBody(secret, ts, body), sig) {
		return nil, ErrBadSignature
	}
	var probe struct {
		Version   *string `json:"version"`
		RequestID *string `json:"requestId"`
		IssuedAt  *string `json:"issuedAt"`
		Input     *struct {
			Action   *string `json:"action"`
			Resource *string `json:"resource"`
		} `json:"input"`
	}
	if !exactKeys(body) || json.Unmarshal(body, &probe) != nil || probe.Version == nil || probe.RequestID == nil ||
		probe.IssuedAt == nil || probe.Input == nil || probe.Input.Action == nil || probe.Input.Resource == nil ||
		*probe.RequestID == "" || utf16Len(*probe.RequestID) > maxRequestIDLen {
		return nil, ErrMalformedRequest
	}
	var req GuardRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, ErrMalformedRequest
	}
	if opts != nil && opts.Seen != nil && opts.Seen(req.RequestID) {
		return nil, ErrReplayedRequest
	}
	return &req, nil
}

// exactKeys rejects an envelope whose top level or input keys differ only in
// case from the protocol names. encoding/json matches keys case
// insensitively; JavaScript does not, so "RequestId" must not stand in for
// "requestId".
func exactKeys(body []byte) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return false
	}
	if !keysExact(top, "version", "requestId", "issuedAt", "input") {
		return false
	}
	var input map[string]json.RawMessage
	if json.Unmarshal(top["input"], &input) != nil {
		return false
	}
	return keysExact(input, "agentId", "action", "resource", "arguments", "agent", "delegation", "source", "ip", "dryRun")
}

// keysExact reports whether every key that case folds to one of names is
// spelled exactly as names spells it.
func keysExact(m map[string]json.RawMessage, names ...string) bool {
	for k := range m {
		for _, n := range names {
			if k != n && bytes.EqualFold([]byte(k), []byte(n)) {
				return false
			}
		}
	}
	return true
}

// VerifyGuardResponse is the client side check of a response: headers,
// freshness, and the HMAC bound to requestID, in constant time.
func VerifyGuardResponse(secret, requestID string, header http.Header, body []byte, opts *VerifyOptions) error {
	tsRaw, sig := header.Get(HeaderResponseTimestamp), header.Get(HeaderResponseSignature)
	if tsRaw == "" || sig == "" {
		return errors.New("missing response signature")
	}
	ts, err := checkFreshness(tsRaw, opts, errors.New("stale response"))
	if errors.Is(err, ErrBadTimestamp) {
		return errors.New("bad response timestamp")
	}
	if err != nil {
		return err
	}
	if !signatureEqual(SignGuardResponseBody(secret, requestID, ts, body), sig) {
		return errors.New(errReasonBadRespSignature)
	}
	return nil
}

// EncodeVerdict returns the wire JSON for v, checked against the strict
// schema so a vendor cannot send what the client would refuse.
func EncodeVerdict(v Verdict) ([]byte, error) {
	body, err := marshalNoEscape(v)
	if err != nil {
		return nil, err
	}
	if _, err := DecodeVerdict(body); err != nil {
		return nil, err
	}
	return body, nil
}

// WriteGuardResponse is the vendor side writer: it encodes v, signs it for
// requestID and writes it with status 200.
func WriteGuardResponse(w http.ResponseWriter, secret, requestID string, v Verdict) error {
	body, err := EncodeVerdict(v)
	if err != nil {
		return err
	}
	for k, vs := range SignGuardResponse(secret, requestID, body, 0) {
		w.Header()[k] = vs
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(body)
	return err
}

// wireVerdict mirrors the strict schema. Raw fields let the decoder tell an
// absent field from null, which the schema refuses.
type wireVerdict struct {
	Decision json.RawMessage `json:"decision"`
	Reason   json.RawMessage `json:"reason"`
	Code     json.RawMessage `json:"code"`
	Guard    json.RawMessage `json:"guard"`
	RuleID   json.RawMessage `json:"ruleId"`
	Metadata json.RawMessage `json:"metadata"`
}

// DecodeVerdict parses a guard response body under the strict 2026-10
// schema: one JSON object, keys spelled exactly, no unknown fields, deny
// needs a non-empty reason, code only on deny, string limits, and metadata of
// at most 16 scalar values. Anything else is an error.
func DecodeVerdict(body []byte) (Verdict, error) {
	if len(body) > MaxBodyBytes {
		return Verdict{}, ErrBodyTooLarge
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(body, &keys); err != nil || keys == nil {
		return Verdict{}, errors.New("verdict is not a JSON object")
	}
	allowed := map[string]bool{"decision": true, "reason": true, "guard": true, "ruleId": true, "metadata": true, "code": true}
	for k := range keys {
		if !allowed[k] {
			return Verdict{}, fmt.Errorf("verdict has unknown field %q", clip(k))
		}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var w wireVerdict
	if err := dec.Decode(&w); err != nil {
		return Verdict{}, errors.New("verdict does not match the schema")
	}
	if _, err := dec.Token(); err != io.EOF {
		return Verdict{}, errors.New("verdict has trailing data")
	}
	var v Verdict
	var err error
	var d string
	if d, err = rawString(w.Decision, "decision", true, maxShortUnits); err != nil {
		return Verdict{}, err
	}
	v.Decision = Decision(d)
	switch v.Decision {
	case Allow, Deny, Escalate:
	default:
		return Verdict{}, errors.New("verdict decision must be allow, deny or escalate")
	}
	if v.Reason, err = rawString(w.Reason, "reason", false, maxReasonUnits); err != nil {
		return Verdict{}, err
	}
	if v.Decision == Deny && v.Reason == "" {
		return Verdict{}, errors.New("deny verdict needs a non-empty reason")
	}
	if w.Code != nil && v.Decision != Deny {
		return Verdict{}, errors.New("verdict field code is allowed on deny only")
	}
	if v.Code, err = rawString(w.Code, "code", false, maxShortUnits); err != nil {
		return Verdict{}, err
	}
	if v.Guard, err = rawString(w.Guard, "guard", false, maxShortUnits); err != nil {
		return Verdict{}, err
	}
	if v.RuleID, err = rawString(w.RuleID, "ruleId", false, maxShortUnits); err != nil {
		return Verdict{}, err
	}
	if v.Metadata, err = rawMetadata(w.Metadata); err != nil {
		return Verdict{}, err
	}
	return v, nil
}

// rawString decodes an optional JSON string field. Present but null, or not
// a string, is an error. Length is counted in UTF-16 units like JavaScript.
func rawString(raw json.RawMessage, name string, required bool, maxUnits int) (string, error) {
	if raw == nil {
		if required {
			return "", fmt.Errorf("verdict field %s is required", name)
		}
		return "", nil
	}
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", fmt.Errorf("verdict field %s must be a string", name)
	}
	if utf16Len(s) > maxUnits {
		return "", fmt.Errorf("verdict field %s is too long", name)
	}
	return s, nil
}

func rawMetadata(raw json.RawMessage) (map[string]any, error) {
	if raw == nil {
		return nil, nil
	}
	if len(raw) == 0 || raw[0] != '{' {
		return nil, errors.New("verdict field metadata must be an object")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, errors.New("verdict field metadata must be an object")
	}
	if len(m) > maxMetadataKeys {
		return nil, errors.New("verdict metadata allows at most 16 keys")
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		var val any
		if err := json.Unmarshal(v, &val); err != nil {
			return nil, errors.New("verdict metadata value is invalid")
		}
		switch val.(type) {
		case string, float64, bool:
			out[k] = val
		default:
			return nil, errors.New("verdict metadata values must be strings, numbers or booleans")
		}
	}
	return out, nil
}

// utf16Len counts UTF-16 code units, the unit JavaScript string limits use.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// marshalNoEscape encodes like JSON.stringify: no HTML escaping, no trailing
// newline.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// newRequestID returns a random RFC 4122 version 4 UUID, the format the
// TypeScript client sends.
func newRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// encodeRequest builds the signed request envelope body.
func encodeRequest(requestID string, issued time.Time, in Input) ([]byte, error) {
	return marshalNoEscape(GuardRequest{
		Version:   ProtocolVersion,
		RequestID: requestID,
		IssuedAt:  issued.UTC().Format(issuedAtLayout),
		Input:     in.normalized(),
	})
}
