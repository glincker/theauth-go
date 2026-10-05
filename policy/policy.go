// Package policy is a small, dependency-free authorization engine: JSON
// policy documents of allow and deny statements over action and resource
// globs, evaluated with explicit-deny-wins and default-deny semantics.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Version is the only policy document version this package understands.
const Version = "1"

// Limits that bound parser and matcher work on untrusted documents.
const (
	MaxDocumentBytes = 1 << 20
	MaxStatements    = 256
	MaxPatternLen    = 512
	MaxListLen       = 256
)

// Effect says whether a matching statement allows or denies.
type Effect string

// Statement effects.
const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

// Condition operators.
const (
	OpEquals      = "equals"
	OpNotEquals   = "not_equals"
	OpIn          = "in"
	OpNotIn       = "not_in"
	OpIPCIDR      = "ip_cidr"
	OpNotIPCIDR   = "not_ip_cidr"
	OpTimeWindow  = "time_window"
	OpDailyWindow = "daily_window"
)

// ErrInvalid wraps every policy document validation failure.
var ErrInvalid = errors.New("policy: invalid document")

// Condition narrows a statement. Key names a request attribute ("ip" is the
// client address). Values may contain {var} references.
type Condition struct {
	Op     string   `json:"op"`
	Key    string   `json:"key,omitempty"`
	Values []string `json:"values"`
}

// Statement is one allow or deny rule.
type Statement struct {
	ID         string      `json:"id,omitempty"`
	Effect     Effect      `json:"effect"`
	Actions    []string    `json:"actions"`
	Resources  []string    `json:"resources"`
	Conditions []Condition `json:"conditions,omitempty"`
}

// Policy is a versioned document of statements.
type Policy struct {
	Version    string      `json:"version"`
	ID         string      `json:"id,omitempty"`
	Statements []Statement `json:"statements"`
}

// Parse decodes and validates a JSON policy document.
func Parse(data []byte) (*Policy, error) {
	if len(data) > MaxDocumentBytes {
		return nil, fmt.Errorf("%w: document exceeds %d bytes", ErrInvalid, MaxDocumentBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Marshal encodes the policy as indented JSON after validating it.
func (p *Policy) Marshal() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("policy: marshal: %w", err)
	}
	return b, nil
}

// Validate checks version, effects, patterns and conditions.
func (p *Policy) Validate() error {
	if p.Version != Version {
		return fmt.Errorf("%w: version must be %q, got %q", ErrInvalid, Version, p.Version)
	}
	if len(p.Statements) > MaxStatements {
		return fmt.Errorf("%w: more than %d statements", ErrInvalid, MaxStatements)
	}
	for i, s := range p.Statements {
		if err := s.validate(); err != nil {
			return fmt.Errorf("%w: statement %d: %v", ErrInvalid, i, err)
		}
	}
	return nil
}

func (s Statement) validate() error {
	if s.Effect != Allow && s.Effect != Deny {
		return fmt.Errorf("effect must be allow or deny, got %q", s.Effect)
	}
	if err := checkPatterns("actions", s.Actions); err != nil {
		return err
	}
	if err := checkPatterns("resources", s.Resources); err != nil {
		return err
	}
	if len(s.Conditions) > MaxListLen {
		return errors.New("too many conditions")
	}
	for _, c := range s.Conditions {
		if err := c.validate(); err != nil {
			return err
		}
	}
	return nil
}

func checkPatterns(field string, list []string) error {
	if len(list) == 0 {
		return fmt.Errorf("%s must not be empty", field)
	}
	if len(list) > MaxListLen {
		return fmt.Errorf("%s has more than %d entries", field, MaxListLen)
	}
	for _, v := range list {
		if v == "" || len(v) > MaxPatternLen {
			return fmt.Errorf("%s entry must be 1 to %d bytes", field, MaxPatternLen)
		}
	}
	return nil
}

func (c Condition) validate() error {
	if len(c.Values) > MaxListLen {
		return errors.New("condition has too many values")
	}
	for _, v := range c.Values {
		if len(v) > MaxPatternLen {
			return errors.New("condition value too long")
		}
	}
	switch c.Op {
	case OpEquals, OpNotEquals:
		if c.Key == "" || len(c.Values) != 1 {
			return fmt.Errorf("%s needs a key and exactly one value", c.Op)
		}
	case OpIn, OpNotIn:
		if c.Key == "" || len(c.Values) == 0 {
			return fmt.Errorf("%s needs a key and at least one value", c.Op)
		}
	case OpIPCIDR, OpNotIPCIDR:
		if len(c.Values) == 0 {
			return fmt.Errorf("%s needs at least one CIDR", c.Op)
		}
		for _, v := range c.Values {
			if _, err := netip.ParsePrefix(v); err != nil {
				return fmt.Errorf("%s: bad CIDR %q", c.Op, v)
			}
		}
	case OpTimeWindow:
		if len(c.Values) != 2 || (c.Values[0] == "" && c.Values[1] == "") {
			return errors.New("time_window needs [start, end] RFC 3339, one may be empty")
		}
		for _, v := range c.Values {
			if v == "" {
				continue
			}
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				return fmt.Errorf("time_window: bad time %q", v)
			}
		}
	case OpDailyWindow:
		if len(c.Values) != 2 {
			return errors.New("daily_window needs [start, end] as HH:MM UTC")
		}
		for _, v := range c.Values {
			if _, err := parseClock(v); err != nil {
				return fmt.Errorf("daily_window: bad time %q", v)
			}
		}
	default:
		return fmt.Errorf("unknown condition op %q", c.Op)
	}
	return nil
}

func parseClock(v string) (int, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("policy: parse clock: %w", err)
	}
	return t.Hour()*60 + t.Minute(), nil
}
