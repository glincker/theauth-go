package as

import (
	"errors"

	"github.com/glincker/theauth-go/internal/models"
)

// metadata.go: RFC 8414 authorization server metadata document.

// ASMetadata is the JSON document served at
// /.well-known/oauth-authorization-server. Field names and shape follow
// RFC 8414 section 2. Optional fields are omitted when empty so consumers
// parsing the document with a strict library stay happy.
type ASMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ServiceDocumentation              string   `json:"service_documentation,omitempty"`
	UILocalesSupported                []string `json:"ui_locales_supported,omitempty"`
}

// ASMetadataDoc builds the metadata document. The result is
// deterministic across calls so handler caching is trivial.
func (s *Service) ASMetadataDoc() (ASMetadata, error) {
	if s == nil {
		return ASMetadata{}, errors.New("theauth: authorization server not configured")
	}
	scopes := map[string]struct{}{}
	for _, r := range s.Cfg.Resources {
		for _, sc := range r.Scopes {
			scopes[sc] = struct{}{}
		}
	}
	scopeList := make([]string, 0, len(scopes))
	for sc := range scopes {
		scopeList = append(scopeList, sc)
	}
	return ASMetadata{
		Issuer:                s.Cfg.Issuer,
		AuthorizationEndpoint: s.Cfg.Issuer + "/oauth/authorize",
		TokenEndpoint:         s.Cfg.Issuer + "/oauth/token",
		RegistrationEndpoint:  s.Cfg.Issuer + "/oauth/register",
		IntrospectionEndpoint: s.Cfg.Issuer + "/oauth/introspect",
		RevocationEndpoint:    s.Cfg.Issuer + "/oauth/revoke",
		JwksURI:               s.Cfg.Issuer + "/oauth/jwks",
		ResponseTypesSupported: []string{
			models.ResponseTypeCode,
		},
		GrantTypesSupported: s.grantTypesAdvertised(),
		TokenEndpointAuthMethodsSupported: []string{
			models.ClientAuthSecretBasic,
			models.ClientAuthSecretPost,
			models.ClientAuthNone,
		},
		CodeChallengeMethodsSupported: []string{"S256"},
		ScopesSupported:               scopeList,
	}, nil
}

// grantTypesAdvertised returns the grant types this AS supports. Phase
// 1+2 supports authorization_code and refresh_token unconditionally;
// phase 3+4 adds client_credentials and the RFC 8693 token-exchange URN
// when the AgentPolicy is configured.
func (s *Service) grantTypesAdvertised() []string {
	out := []string{models.GrantTypeAuthorizationCode, models.GrantTypeRefreshToken}
	if s.AgentPolicy != nil {
		out = append(out, models.GrantTypeClientCredentials, models.GrantTypeTokenExchange)
	}
	return out
}
