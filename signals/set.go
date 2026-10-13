package signals

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/internal/jwt"
)

// TypeSET is the JOSE typ header of a Security Event Token (RFC 8417
// section 2.3 and RFC 9493 recommend explicit typing).
const TypeSET = "secevent+jwt"

// Signer signs the claims of a SET. The typ header passed is TypeSET.
type Signer interface {
	SignSET(payload map[string]any) (string, error)
}

// SignerFunc adapts a function to Signer.
type SignerFunc func(payload map[string]any) (string, error)

// SignSET implements Signer.
func (f SignerFunc) SignSET(payload map[string]any) (string, error) { return f(payload) }

// NewKeySigner signs SETs with key under the given kid and JWS algorithm
// (EdDSA, ES256 or RS256).
func NewKeySigner(kid, alg string, key crypto.Signer) Signer {
	return SignerFunc(func(payload map[string]any) (string, error) {
		return jwt.SignPayloadWith(payload, TypeSET, kid, alg, key)
	})
}

// KeyResolver maps a JWS kid to its algorithm and public key.
type KeyResolver = jwt.KeyResolver

// SET is a decoded Security Event Token.
type SET struct {
	Issuer   string
	Audience []string
	IssuedAt time.Time
	JTI      string
	// TransactionID is the optional txn claim.
	TransactionID string
	// EventTime is the optional toe claim.
	EventTime *time.Time
	// Events holds the events keyed by event type URI.
	Events []Event
	// Raw is the compact serialization the SET was parsed from or signed
	// into. It is empty for an unsigned value.
	Raw string
}

// Event is one entry of the SET events claim.
type Event struct {
	// Type is the event type URI.
	Type string
	// Subject is the subject the event is about. Zero means none.
	Subject Subject
	// Properties are the event specific members (reason_admin, ...).
	Properties map[string]any
}

// Payload renders the event payload object (subject plus properties).
func (e Event) Payload() map[string]any {
	out := make(map[string]any, len(e.Properties)+1)
	for k, v := range e.Properties {
		out[k] = v
	}
	if !e.Subject.IsZero() {
		out["subject"] = e.Subject
	}
	return out
}

// Claims renders the registered and events claims of s.
func (s SET) Claims() map[string]any {
	c := map[string]any{
		"jti": s.JTI,
		"iat": s.IssuedAt.Unix(),
	}
	if s.Issuer != "" {
		c["iss"] = s.Issuer
	}
	switch len(s.Audience) {
	case 0:
	case 1:
		c["aud"] = s.Audience[0]
	default:
		c["aud"] = s.Audience
	}
	if s.TransactionID != "" {
		c["txn"] = s.TransactionID
	}
	if s.EventTime != nil {
		c["toe"] = s.EventTime.Unix()
	}
	events := make(map[string]any, len(s.Events))
	for _, e := range s.Events {
		events[e.Type] = e.Payload()
	}
	c["events"] = events
	return c
}

// Sign serializes and signs s. It sets Raw on success.
func (s *SET) Sign(signer Signer) (string, error) {
	if signer == nil {
		return "", errors.New("signals: nil signer")
	}
	if s.JTI == "" {
		return "", errors.New("signals: SET requires a jti")
	}
	if len(s.Events) == 0 {
		return "", errors.New("signals: SET requires at least one event")
	}
	tok, err := signer.SignSET(s.Claims())
	if err != nil {
		return "", fmt.Errorf("signals: sign SET: %w", err)
	}
	s.Raw = tok
	return tok, nil
}

// VerifyOptions tunes Verify.
type VerifyOptions struct {
	// Issuer, when non-empty, must equal the iss claim.
	Issuer string
	// Audience, when non-empty, must appear in the aud claim.
	Audience string
	// Now overrides the clock. Zero means time.Now.
	Now time.Time
	// MaxAge, when positive, rejects SETs whose iat is older than it.
	// RFC 8417 defines no exp, so this is the only age bound.
	MaxAge time.Duration
	// Skew tolerates clock drift on iat in the future. Default 1 minute.
	Skew time.Duration
}

// Verify authenticates token (signature, typ secevent+jwt) and validates the
// registered claims. A SET has no exp requirement.
func Verify(token string, resolve KeyResolver, opts VerifyOptions) (*SET, error) {
	_, payload, err := jwt.VerifySignature(token, resolve, TypeSET)
	if err != nil {
		return nil, err
	}
	return parsePayload(token, payload, opts)
}

func parsePayload(token string, payload []byte, opts VerifyOptions) (*SET, error) {
	var raw struct {
		Iss    string                     `json:"iss"`
		Aud    json.RawMessage            `json:"aud"`
		Iat    *int64                     `json:"iat"`
		Jti    string                     `json:"jti"`
		Txn    string                     `json:"txn"`
		Toe    *int64                     `json:"toe"`
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("signals: payload parse: %w", err)
	}
	if raw.Jti == "" {
		return nil, errors.New("signals: SET missing jti")
	}
	if raw.Iat == nil {
		return nil, errors.New("signals: SET missing iat")
	}
	if raw.Iss == "" {
		return nil, errors.New("signals: SET missing iss")
	}
	if len(raw.Events) == 0 {
		return nil, errors.New("signals: SET missing events")
	}
	s := &SET{Issuer: raw.Iss, JTI: raw.Jti, TransactionID: raw.Txn, IssuedAt: time.Unix(*raw.Iat, 0).UTC(), Raw: token}
	if raw.Toe != nil {
		t := time.Unix(*raw.Toe, 0).UTC()
		s.EventTime = &t
	}
	if len(raw.Aud) > 0 {
		var one string
		var many []string
		switch {
		case json.Unmarshal(raw.Aud, &one) == nil:
			s.Audience = []string{one}
		case json.Unmarshal(raw.Aud, &many) == nil:
			s.Audience = many
		default:
			return nil, errors.New("signals: SET aud malformed")
		}
	}
	for typ, body := range raw.Events {
		ev := Event{Type: typ}
		var props map[string]json.RawMessage
		if err := json.Unmarshal(body, &props); err != nil {
			return nil, fmt.Errorf("signals: event %q payload: %w", typ, err)
		}
		if sub, ok := props["subject"]; ok {
			if err := json.Unmarshal(sub, &ev.Subject); err != nil {
				return nil, fmt.Errorf("signals: event %q subject: %w", typ, err)
			}
			delete(props, "subject")
		}
		if len(props) > 0 {
			ev.Properties = make(map[string]any, len(props))
			for k, v := range props {
				var a any
				if err := json.Unmarshal(v, &a); err == nil {
					ev.Properties[k] = a
				}
			}
		}
		s.Events = append(s.Events, ev)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := opts.Skew
	if skew == 0 {
		skew = time.Minute
	}
	if s.IssuedAt.After(now.Add(skew)) {
		return nil, errors.New("signals: SET iat is in the future")
	}
	if opts.MaxAge > 0 && now.Sub(s.IssuedAt) > opts.MaxAge+skew {
		return nil, errors.New("signals: SET is too old")
	}
	if opts.Issuer != "" && s.Issuer != opts.Issuer {
		return nil, fmt.Errorf("signals: SET issuer %q not accepted", s.Issuer)
	}
	if opts.Audience != "" {
		found := false
		for _, a := range s.Audience {
			if a == opts.Audience {
				found = true
			}
		}
		if !found {
			return nil, errors.New("signals: SET audience mismatch")
		}
	}
	return s, nil
}

// PeekIssuer returns the unverified iss claim of a compact SET. Receivers use
// it only to pick which JWKS to verify against; never trust it otherwise.
func PeekIssuer(token string) (string, error) {
	parts := splitJWS(token)
	if parts == nil {
		return "", errors.New("signals: malformed SET")
	}
	payload, err := b64(parts[1])
	if err != nil {
		return "", errors.New("signals: malformed SET payload")
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil || c.Iss == "" {
		return "", errors.New("signals: SET missing iss")
	}
	return c.Iss, nil
}
