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
	// TokenEndpointAuthSigningAlgValuesSupported lists the JWS signing
	// algorithms supported for private_key_jwt and client_secret_jwt
	// client authentication. Omitted when JWT client auth is disabled.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	ServiceDocumentation                       string   `json:"service_documentation,omitempty"`
	UILocalesSupported                         []string `json:"ui_locales_supported,omitempty"`
	// DPoPSigningAlgValuesSupported is the RFC 9449 section 5.1 metadata
	// field advertising the proof-JWT signing algorithms this AS
	// accepts. Omitted when DPoP is disabled.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	// PAR (RFC 9126) fields. Both are omitted when PAR is disabled.
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests bool   `json:"require_pushed_authorization_requests,omitempty"`

	// JAR (RFC 9101) fields. Omitted when JAR is disabled.
	RequestParameterSupported              bool     `json:"request_parameter_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`
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
	var dpopAlgs []string
	if s.dpopSvc != nil && s.Cfg.DPoP != nil {
		// Surface the operator-configured allow list verbatim so the
		// metadata document and the actual verifier never disagree.
		if len(s.Cfg.DPoP.AllowedSignAlgs) == 0 {
			dpopAlgs = append([]string(nil), defaultDPoPAdvertisedAlgs...)
		} else {
			dpopAlgs = append([]string(nil), s.Cfg.DPoP.AllowedSignAlgs...)
		}
	}
	// Build PAR fields.
	var parEndpoint string
	var requirePAR bool
	if s.IsPAREnabled() {
		parEndpoint = s.Cfg.Issuer + "/oauth/par"
		requirePAR = s.Cfg.PAR.RequirePAR
	}

	// Build JAR fields.
	var requestParamSupported bool
	var jarAlgs []string
	if s.IsJAREnabled() {
		requestParamSupported = true
		jarAlgs = s.jarAlgorithmsAdvertised()
	}

	authMethods := []string{
		models.ClientAuthSecretBasic,
		models.ClientAuthSecretPost,
		models.ClientAuthNone,
	}
	var jwtAuthAlgs []string
	if s.Cfg.JWTBearer != nil {
		authMethods = append(authMethods, models.ClientAuthPrivateKeyJWT, models.ClientAuthClientSecretJWT)
		jwtAuthAlgs = []string{"ES256", "ES384", "RS256", "PS256", "EdDSA"}
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
		GrantTypesSupported:                        s.grantTypesAdvertised(),
		TokenEndpointAuthMethodsSupported:          authMethods,
		TokenEndpointAuthSigningAlgValuesSupported: jwtAuthAlgs,
		CodeChallengeMethodsSupported:              []string{"S256"},
		ScopesSupported:                            scopeList,
		DPoPSigningAlgValuesSupported:              dpopAlgs,
		PushedAuthorizationRequestEndpoint:         parEndpoint,
		RequirePushedAuthorizationRequests:         requirePAR,
		RequestParameterSupported:                  requestParamSupported,
		RequestObjectSigningAlgValuesSupported:     jarAlgs,
	}, nil
}

// defaultDPoPAdvertisedAlgs mirrors dpop.DefaultAllowedAlgs. Duplicated
// here so the metadata document does not need to import the dpop
// package (avoids an import cycle in tests that fixture only this
// helper).
var defaultDPoPAdvertisedAlgs = []string{"ES256", "ES384", "RS256", "PS256", "EdDSA"}

// grantTypesAdvertised returns the grant types this AS supports. Phase
// 1+2 supports authorization_code and refresh_token unconditionally;
// phase 3+4 adds client_credentials and the RFC 8693 token-exchange URN
// when the AgentPolicy is configured; RFC 7523 adds the jwt-bearer URN
// when JWTBearer is configured.
func (s *Service) grantTypesAdvertised() []string {
	out := []string{models.GrantTypeAuthorizationCode, models.GrantTypeRefreshToken}
	if s.AgentPolicy != nil {
		out = append(out, models.GrantTypeClientCredentials, models.GrantTypeTokenExchange)
	}
	if s.Cfg.JWTBearer != nil {
		out = append(out, models.GrantTypeJWTBearer)
	}
	return out
}
