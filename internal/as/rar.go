package as

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/rar"
)

// rar.go implements RFC 9396 Rich Authorization Requests. internal/rar owns the data model; this
// file decides which types the server accepts and carries approved details through the code, access
// token and refresh token.

// RARConfig enables authorization_details handling.
type RARConfig struct {
	// Types lists the authorization_details types this server understands. Any other type is refused.
	Types []string

	MaxDetails int
}

func validateRAR(c *RARConfig) error {
	if c == nil {
		return nil
	}
	if len(c.Types) == 0 {
		return errors.New("theauth: RAR.Types must list at least one authorization_details type")
	}
	seen := map[string]struct{}{}
	for _, t := range c.Types {
		if t == "" {
			return errors.New("theauth: RAR.Types must not contain an empty type")
		}
		if _, dup := seen[t]; dup {
			return fmt.Errorf("theauth: RAR.Types lists %q twice", t)
		}
		seen[t] = struct{}{}
	}
	if c.MaxDetails < 0 {
		return errors.New("theauth: RAR.MaxDetails must not be negative")
	}
	if c.MaxDetails == 0 {
		c.MaxDetails = rar.DefaultMaxDetails
	}
	return nil
}

func rarError(format string, a ...any) error {
	return fmt.Errorf("%w: %s", models.ErrOAuthInvalidAuthorizationDetails, fmt.Sprintf(format, a...))
}

// RARTypes returns the supported authorization_details types, or nil when RAR is off.
func (s *Service) RARTypes() []string {
	if s == nil || s.Cfg.RAR == nil {
		return nil
	}
	return append([]string(nil), s.Cfg.RAR.Types...)
}

// ValidateClientRARTypes checks a client's authorization_details_types against the supported set.
func (s *Service) ValidateClientRARTypes(types []string) error {
	if len(types) == 0 {
		return nil
	}
	if s.Cfg.RAR == nil {
		return errors.New("authorization_details is not enabled on this server")
	}
	for _, t := range types {
		if !stringIn(s.Cfg.RAR.Types, t) {
			return fmt.Errorf("authorization_details type %q is not supported", t)
		}
	}
	return nil
}

func stringIn(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// parseAuthorizationDetails parses and vets a raw authorization_details value. It returns nil, nil
// for an empty value.
func (s *Service) parseAuthorizationDetails(client *models.OAuthClient, raw string) ([]rar.Detail, []byte, error) {
	if raw == "" {
		return nil, nil, nil
	}
	if s.Cfg.RAR == nil {
		return nil, nil, rarError("authorization_details is not supported")
	}
	list, err := rar.Parse(raw, s.Cfg.RAR.MaxDetails)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", models.ErrOAuthInvalidAuthorizationDetails, err)
	}
	for _, d := range list {
		if !stringIn(s.Cfg.RAR.Types, d.Type) {
			return nil, nil, rarError("type %q is not supported", d.Type)
		}
		if client != nil && len(client.AuthorizationDetailsTypes) > 0 && !stringIn(client.AuthorizationDetailsTypes, d.Type) {
			return nil, nil, rarError("client may not request type %q", d.Type)
		}
	}
	enc, err := rar.Marshal(list)
	if err != nil {
		return nil, nil, rarError("cannot encode value")
	}
	return list, enc, nil
}

// narrowAuthorizationDetails applies a token request's authorization_details to the granted details
// (RFC 9396 section 6.1). An empty request keeps the grant as is; asking for details never granted
// fails.
func (s *Service) narrowAuthorizationDetails(client *models.OAuthClient, requestedRaw string, granted []byte) ([]byte, error) {
	if requestedRaw == "" {
		return granted, nil
	}
	requested, _, err := s.parseAuthorizationDetails(client, requestedRaw)
	if err != nil {
		return nil, err
	}
	grant, err := rar.ParseBytes(granted, 1<<10)
	if err != nil || len(grant) == 0 {
		return nil, rarError("no authorization_details were granted")
	}
	eff, ok := rar.Narrow(requested, grant)
	if !ok {
		return nil, rarError("requested details exceed the grant")
	}
	return rar.Marshal(eff)
}

// authorizationDetailsClaim turns stored details into the authorization_details claim, or nil.
func authorizationDetailsClaim(stored []byte) (any, error) {
	if len(stored) == 0 {
		return nil, nil
	}
	list, err := rar.ParseBytes(stored, 1<<10)
	if err != nil {
		return nil, err
	}
	return rar.ToAny(list)
}

// authorizationDetailsRaw returns the claim as JSON for token responses and introspection, or nil.
func authorizationDetailsRaw(extra map[string]any) json.RawMessage {
	v, ok := extra["authorization_details"]
	if !ok || v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
