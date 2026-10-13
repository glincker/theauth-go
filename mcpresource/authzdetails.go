package mcpresource

import (
	"encoding/json"
	"errors"
	"fmt"
)

// AuthorizationDetail is one RFC 9396 authorization_details object. The
// common fields are decoded; Raw holds the complete object so
// type-specific members (for example creditorName) stay reachable.
type AuthorizationDetail struct {
	Type       string
	Locations  []string
	Actions    []string
	Datatypes  []string
	Identifier string
	Privileges []string
	Raw        json.RawMessage
}

// AuthorizationDetails returns the RFC 9396 authorization_details carried by
// the access token or, for tokens that triggered introspection, the
// introspection response. The slice is a copy; changing it does not affect
// the principal. A nil result means the token carries none.
func (p *Principal) AuthorizationDetails() []AuthorizationDetail {
	if p == nil || len(p.authorizationDetails) == 0 {
		return nil
	}
	out := make([]AuthorizationDetail, len(p.authorizationDetails))
	for i, d := range p.authorizationDetails {
		out[i] = AuthorizationDetail{
			Type:       d.Type,
			Locations:  append([]string(nil), d.Locations...),
			Actions:    append([]string(nil), d.Actions...),
			Datatypes:  append([]string(nil), d.Datatypes...),
			Identifier: d.Identifier,
			Privileges: append([]string(nil), d.Privileges...),
			Raw:        append(json.RawMessage(nil), d.Raw...),
		}
	}
	return out
}

// parseAuthorizationDetails decodes the raw authorization_details array. It
// fails closed on a malformed value or an element without the REQUIRED type
// member (RFC 9396 section 2).
func parseAuthorizationDetails(raw json.RawMessage) ([]AuthorizationDetail, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("mcpresource: authorization_details must be an array: %w", err)
	}
	out := make([]AuthorizationDetail, 0, len(items))
	for _, it := range items {
		var d struct {
			Type       string   `json:"type"`
			Locations  []string `json:"locations"`
			Actions    []string `json:"actions"`
			Datatypes  []string `json:"datatypes"`
			Identifier string   `json:"identifier"`
			Privileges []string `json:"privileges"`
		}
		if err := json.Unmarshal(it, &d); err != nil {
			return nil, fmt.Errorf("mcpresource: authorization_details element: %w", err)
		}
		if d.Type == "" {
			return nil, errors.New("mcpresource: authorization_details element missing type")
		}
		out = append(out, AuthorizationDetail{
			Type: d.Type, Locations: d.Locations, Actions: d.Actions, Datatypes: d.Datatypes,
			Identifier: d.Identifier, Privileges: d.Privileges, Raw: append(json.RawMessage(nil), it...),
		})
	}
	return out, nil
}
