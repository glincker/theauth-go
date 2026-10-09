// Package rar implements the data model for OAuth 2.0 Rich Authorization
// Requests (RFC 9396): parsing the authorization_details parameter,
// serialising it for storage and token claims, and the narrowing rules used
// when a client asks for less than it was granted.
//
// The package knows nothing about the authorization server. Which types are
// acceptable, and what each type means, is decided by the caller.
package rar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
)

// DefaultMaxDetails bounds how many objects one request may carry. The
// parameter arrives from unauthenticated callers, so it is capped.
const DefaultMaxDetails = 16

// MaxEncodedBytes bounds the size of an authorization_details value.
const MaxEncodedBytes = 16 << 10

// ErrInvalid wraps every parse or validation failure. It maps to the RFC 9396
// section 5 error code invalid_authorization_details.
var ErrInvalid = errors.New("invalid_authorization_details")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Detail is one authorization details object. Type is required. The common
// data fields of RFC 9396 section 2.2 are typed; every other member lands in
// Fields so type-specific data survives a round trip untouched.
type Detail struct {
	Type       string
	Locations  []string
	Actions    []string
	DataTypes  []string
	Identifier string
	Privileges []string
	Fields     map[string]any
}

// MarshalJSON emits the object with Type first-class and Fields merged in.
// Registered members win over a colliding Fields key.
func (d Detail) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(d.Fields)+6)
	for k, v := range d.Fields {
		m[k] = v
	}
	m["type"] = d.Type
	setList := func(k string, v []string) {
		if len(v) > 0 {
			m[k] = v
		}
	}
	setList("locations", d.Locations)
	setList("actions", d.Actions)
	setList("datatypes", d.DataTypes)
	setList("privileges", d.Privileges)
	if d.Identifier != "" {
		m["identifier"] = d.Identifier
	}
	return json.Marshal(m)
}

// UnmarshalJSON parses one object and rejects members of the wrong shape.
func (d *Detail) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return invalid("each entry must be a JSON object")
	}
	var out Detail
	for k, v := range raw {
		var err error
		switch k {
		case "type":
			err = json.Unmarshal(v, &out.Type)
		case "locations":
			err = json.Unmarshal(v, &out.Locations)
		case "actions":
			err = json.Unmarshal(v, &out.Actions)
		case "datatypes":
			err = json.Unmarshal(v, &out.DataTypes)
		case "privileges":
			err = json.Unmarshal(v, &out.Privileges)
		case "identifier":
			err = json.Unmarshal(v, &out.Identifier)
		default:
			var x any
			if err = json.Unmarshal(v, &x); err == nil {
				if out.Fields == nil {
					out.Fields = map[string]any{}
				}
				out.Fields[k] = x
			}
		}
		if err != nil {
			return invalid("member %q has the wrong type", k)
		}
	}
	if out.Type == "" {
		return invalid("type is required")
	}
	*d = out
	return nil
}

// Parse decodes an authorization_details value: a non-empty JSON array of
// objects. max <= 0 selects DefaultMaxDetails. The empty string yields nil.
func Parse(raw string, max int) ([]Detail, error) {
	if raw == "" {
		return nil, nil
	}
	return ParseBytes([]byte(raw), max)
}

// ParseBytes is Parse for a byte slice.
func ParseBytes(raw []byte, max int) ([]Detail, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if max <= 0 {
		max = DefaultMaxDetails
	}
	if len(raw) > MaxEncodedBytes {
		return nil, invalid("value exceeds %d bytes", MaxEncodedBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var list []Detail
	if err := dec.Decode(&list); err != nil {
		if errors.Is(err, ErrInvalid) {
			return nil, err
		}
		return nil, invalid("value must be a JSON array of objects")
	}
	if dec.More() {
		return nil, invalid("trailing data after the array")
	}
	if len(list) == 0 {
		return nil, invalid("array must not be empty")
	}
	if len(list) > max {
		return nil, invalid("at most %d entries are allowed", max)
	}
	return list, nil
}

// Marshal serialises details for storage. An empty slice yields nil.
func Marshal(list []Detail) ([]byte, error) {
	if len(list) == 0 {
		return nil, nil
	}
	return json.Marshal(list)
}

// Types returns the distinct types in list, sorted.
func Types(list []Detail) []string {
	seen := map[string]struct{}{}
	for _, d := range list {
		seen[d.Type] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Narrow reports whether every requested detail is covered by some granted
// detail and returns the effective details to issue. A requested detail is
// covered by a granted one when the type matches and each attribute is no
// broader: list attributes must be subsets, scalar attributes must be equal.
// An attribute the request omits is inherited from the grant, so asking for
// "type only" yields the full grant of that type, never more.
func Narrow(requested, granted []Detail) ([]Detail, bool) {
	out := make([]Detail, 0, len(requested))
	for _, r := range requested {
		var eff Detail
		ok := false
		for _, g := range granted {
			if e, covered := narrowOne(r, g); covered {
				eff, ok = e, true
				break
			}
		}
		if !ok {
			return nil, false
		}
		out = append(out, eff)
	}
	return out, true
}

func narrowOne(r, g Detail) (Detail, bool) {
	if r.Type != g.Type {
		return Detail{}, false
	}
	e := Detail{Type: g.Type}
	var ok bool
	if e.Locations, ok = narrowList(r.Locations, g.Locations); !ok {
		return Detail{}, false
	}
	if e.Actions, ok = narrowList(r.Actions, g.Actions); !ok {
		return Detail{}, false
	}
	if e.DataTypes, ok = narrowList(r.DataTypes, g.DataTypes); !ok {
		return Detail{}, false
	}
	if e.Privileges, ok = narrowList(r.Privileges, g.Privileges); !ok {
		return Detail{}, false
	}
	switch {
	case r.Identifier == "":
		e.Identifier = g.Identifier
	case g.Identifier == "" || g.Identifier == r.Identifier:
		// A grant without an identifier covers any identifier.
		e.Identifier = r.Identifier
	default:
		return Detail{}, false
	}
	for k, rv := range r.Fields {
		gv, has := g.Fields[k]
		if has && !reflect.DeepEqual(rv, gv) {
			return Detail{}, false
		}
		if !has && len(g.Fields) > 0 {
			// The grant constrains type-specific data but not this member:
			// refuse rather than guess whether it widens the grant.
			return Detail{}, false
		}
	}
	if len(g.Fields) > 0 || len(r.Fields) > 0 {
		e.Fields = map[string]any{}
		for k, v := range g.Fields {
			e.Fields[k] = v
		}
		for k, v := range r.Fields {
			e.Fields[k] = v
		}
	}
	return e, true
}

// narrowList returns the effective list: the request's when it is a subset of
// the grant, the grant's when the request omits it. A grant with no list
// allows any request list.
func narrowList(req, grant []string) ([]string, bool) {
	if len(req) == 0 {
		return grant, true
	}
	if len(grant) == 0 {
		return req, true
	}
	allowed := make(map[string]struct{}, len(grant))
	for _, v := range grant {
		allowed[v] = struct{}{}
	}
	for _, v := range req {
		if _, ok := allowed[v]; !ok {
			return nil, false
		}
	}
	return req, true
}

// ToAny converts details into the generic JSON shape ([]any of map[string]any)
// suitable for embedding in jwt.Claims.Extra, which round-trips through
// encoding/json unchanged.
func ToAny(list []Detail) ([]any, error) {
	b, err := Marshal(list)
	if err != nil || b == nil {
		return nil, err
	}
	var out []any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// FromAny is the inverse of ToAny, for reading the claim back from a verified
// token. Anything that does not parse yields nil.
func FromAny(v any) []Detail {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	list, err := ParseBytes(b, 1<<10)
	if err != nil {
		return nil
	}
	return list
}
