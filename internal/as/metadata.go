package as

import (
	"errors"
	"slices"
	"sort"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// ASMetadata is the RFC 8414 document served at /.well-known/oauth-authorization-server. Optional
// fields are omitted when empty.
type ASMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	// RegistrationEndpoint is advertised only when the operator opted in to DCR (RegistrationTokens or
	// AllowAnonymousRegistration).
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// ClientIDMetadataDocumentSupported advertises CIMD support.
	ClientIDMetadataDocumentSupported bool `json:"client_id_metadata_document_supported,omitempty"`

	// AuthorizationResponseIssParameterSupported advertises the RFC 9207 iss parameter on
	// authorization responses.
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported,omitempty"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	// TokenEndpointAuthSigningAlgValuesSupported lists the JWS algorithms for private_key_jwt client
	// auth. Omitted when JWT client auth is off.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	ACRValuesSupported                         []string `json:"acr_values_supported,omitempty"`
	ServiceDocumentation                       string   `json:"service_documentation,omitempty"`
	UILocalesSupported                         []string `json:"ui_locales_supported,omitempty"`
	// DPoPSigningAlgValuesSupported is the RFC 9449 section 5.1 list of accepted proof algorithms.
	// Omitted when DPoP is off.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	// PAR fields are omitted when PAR is disabled.
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests bool   `json:"require_pushed_authorization_requests,omitempty"`

	// JAR fields are omitted when JAR is disabled.
	RequestParameterSupported              bool     `json:"request_parameter_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`

	// CIBA fields (RFC 9509) are omitted when CIBA is disabled.
	BackchannelAuthenticationEndpoint      string   `json:"backchannel_authentication_endpoint,omitempty"`
	BackchannelTokenDeliveryModesSupported []string `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackchannelUserCodeParameterSupported  bool     `json:"backchannel_user_code_parameter_supported,omitempty"`

	// DeviceAuthorizationEndpoint (RFC 8628 section 4) is omitted when the device grant is off.
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`

	// AuthorizationDetailsTypesSupported (RFC 9396 section 10) is omitted when RAR is off.
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`

	// OpenID Provider fields (OIDC Discovery 1.0 section 3) are omitted unless Config.OIDC is set.
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
	BackchannelLogoutSupported        bool     `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported bool     `json:"backchannel_logout_session_supported,omitempty"`
}

// ASMetadataDoc builds the metadata document. It is deterministic, so handler caching is trivial.
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
		// The metadata advertises the operator's allow list verbatim, so the document and the verifier
		// never disagree.
		if len(s.Cfg.DPoP.AllowedSignAlgs) == 0 {
			dpopAlgs = append([]string(nil), defaultDPoPAdvertisedAlgs...)
		} else {
			dpopAlgs = append([]string(nil), s.Cfg.DPoP.AllowedSignAlgs...)
		}
	}
	var parEndpoint string
	var requirePAR bool
	if s.IsPAREnabled() {
		parEndpoint = s.Cfg.Issuer + "/oauth/par"
		requirePAR = s.Cfg.PAR.RequirePAR
	}

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
	meta := ASMetadata{
		Issuer:                s.Cfg.Issuer,
		AuthorizationEndpoint: s.Cfg.Issuer + "/oauth/authorize",
		TokenEndpoint:         s.Cfg.Issuer + "/oauth/token",
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
	}

	meta.AuthorizationResponseIssParameterSupported = true
	meta.ClientIDMetadataDocumentSupported = s.Cfg.CIMD != nil
	if len(s.Cfg.RegistrationTokens) > 0 || s.Cfg.AllowAnonymousRegistration {
		meta.RegistrationEndpoint = s.Cfg.Issuer + "/oauth/register"
	}

	if s.Cfg.CIBA != nil {
		if _, ok := s.Storage.(CIBAStorage); ok {
			meta.BackchannelAuthenticationEndpoint = s.Cfg.Issuer + "/oauth/bc-authorize"
			meta.BackchannelTokenDeliveryModesSupported = []string{
				models.CIBADeliveryModePoll,
				models.CIBADeliveryModePing,
			}
			// user_code is not supported in this implementation.
			meta.BackchannelUserCodeParameterSupported = false
		}
	}

	if s.IsDeviceEnabled() {
		meta.DeviceAuthorizationEndpoint = s.Cfg.Issuer + "/oauth/device_authorization"
	}

	meta.AuthorizationDetailsTypesSupported = s.RARTypes()
	meta.ACRValuesSupported = s.acrValuesSupported()
	if s.OIDCEnabled() {
		s.addOIDCMetadata(&meta)
	}

	return meta, nil
}

// defaultDPoPAdvertisedAlgs mirrors dpop.DefaultAllowedAlgs. It is duplicated here to avoid
// importing the dpop package.
var defaultDPoPAdvertisedAlgs = []string{"ES256", "ES384", "RS256", "PS256", "EdDSA"}

// grantTypesAdvertised returns the supported grant types. Authorization code and refresh are always
// on; client_credentials and token exchange need AgentPolicy; jwt-bearer needs JWTBearer; CIBA and
// device add their own when enabled.
func (s *Service) grantTypesAdvertised() []string {
	out := []string{models.GrantTypeAuthorizationCode, models.GrantTypeRefreshToken}
	if s.AgentPolicy != nil {
		out = append(out, models.GrantTypeClientCredentials, models.GrantTypeTokenExchange)
	} else if s.Cfg.IDJAG != nil && len(s.Cfg.IDJAG.Audiences) > 0 {
		out = append(out, models.GrantTypeTokenExchange)
	}
	if s.Cfg.JWTBearer != nil || s.DeviceTokensEnabled() {
		out = append(out, models.GrantTypeJWTBearer)
	}
	if s.Cfg.CIBA != nil {
		if _, ok := s.Storage.(CIBAStorage); ok {
			out = append(out, models.GrantTypeCIBA)
		}
	}
	if s.IsDeviceEnabled() {
		out = append(out, models.GrantTypeDeviceCode)
	}
	return out
}

func (s *Service) addOIDCMetadata(meta *ASMetadata) {
	meta.UserinfoEndpoint = s.Cfg.Issuer + "/oauth/userinfo"
	meta.EndSessionEndpoint = s.Cfg.Issuer + "/oauth/end_session"
	meta.SubjectTypesSupported = []string{models.SubjectTypePublic}
	if len(s.Cfg.OIDC.PairwiseSalt) > 0 {
		meta.SubjectTypesSupported = append(meta.SubjectTypesSupported, models.SubjectTypePairwise)
	}
	meta.IDTokenSigningAlgValuesSupported = s.SigningAlgsAdvertised()
	meta.BackchannelLogoutSupported = true
	meta.BackchannelLogoutSessionSupported = true
	scopes := append(meta.ScopesSupported, ScopeOpenID, ScopeProfile, ScopeEmail)
	sort.Strings(scopes)
	meta.ScopesSupported = slices.Compact(scopes)
	meta.ClaimsSupported = []string{
		"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "at_hash", "sid",
		"name", "given_name", "family_name", "picture", "updated_at", "email", "email_verified",
	}
}
