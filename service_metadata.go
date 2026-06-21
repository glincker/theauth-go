package theauth

import "errors"

// service_metadata.go: RFC 8414 authorization server metadata document.

// ASMetadata is the JSON document served at /.well-known/oauth-authorization-server.
// Field names and shape follow RFC 8414 section 2. Optional fields are
// omitted when empty so consumers parsing the document with a strict library
// stay happy.
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

// ASMetadataDoc builds the metadata document. The result is deterministic
// across calls so handler caching is trivial.
func (a *TheAuth) ASMetadataDoc() (ASMetadata, error) {
	if a.as == nil {
		return ASMetadata{}, errors.New("theauth: authorization server not configured")
	}
	scopes := map[string]struct{}{}
	for _, r := range a.as.cfg.Resources {
		for _, s := range r.Scopes {
			scopes[s] = struct{}{}
		}
	}
	scopeList := make([]string, 0, len(scopes))
	for s := range scopes {
		scopeList = append(scopeList, s)
	}
	return ASMetadata{
		Issuer:                a.as.cfg.Issuer,
		AuthorizationEndpoint: a.as.cfg.Issuer + "/oauth/authorize",
		TokenEndpoint:         a.as.cfg.Issuer + "/oauth/token",
		RegistrationEndpoint:  a.as.cfg.Issuer + "/oauth/register",
		IntrospectionEndpoint: a.as.cfg.Issuer + "/oauth/introspect",
		RevocationEndpoint:    a.as.cfg.Issuer + "/oauth/revoke",
		JwksURI:               a.as.cfg.Issuer + "/oauth/jwks",
		ResponseTypesSupported: []string{
			ResponseTypeCode,
		},
		GrantTypesSupported: []string{
			GrantTypeAuthorizationCode,
			GrantTypeRefreshToken,
		},
		TokenEndpointAuthMethodsSupported: []string{
			ClientAuthSecretBasic,
			ClientAuthSecretPost,
			ClientAuthNone,
		},
		CodeChallengeMethodsSupported: []string{"S256"},
		ScopesSupported:               scopeList,
	}, nil
}
