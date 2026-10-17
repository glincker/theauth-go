package as

import (
	"errors"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// metadata_resource.go serves RFC 9728 protected resource metadata, so a fresh client can find the
// AS that mints tokens for a resource. There is one document per configured ProtectedResource.

// ProtectedResourceMetadata is the JSON document mandated by RFC 9728. Only the required and
// most-used optional fields are declared.
type ProtectedResourceMetadata struct {
	Resource                    string   `json:"resource"`
	AuthorizationServers        []string `json:"authorization_servers"`
	BearerMethodsSupported      []string `json:"bearer_methods_supported"`
	ScopesSupported             []string `json:"scopes_supported,omitempty"`
	ResourceName                string   `json:"resource_name,omitempty"`
	ResourceDocumentation       string   `json:"resource_documentation,omitempty"`
	ResourceSigningAlgValuesSup []string `json:"resource_signing_alg_values_supported,omitempty"`
	JwksURI                     string   `json:"jwks_uri,omitempty"`
}

// ProtectedResourceMetadataDoc builds the RFC 9728 document for the resource with the given
// identifier, or errors if it is not configured.
func (s *Service) ProtectedResourceMetadataDoc(resourceID string) (ProtectedResourceMetadata, error) {
	if s == nil {
		return ProtectedResourceMetadata{}, errors.New("theauth: authorization server not configured")
	}
	resource, ok := s.ResourceByIdentifier(resourceID)
	if !ok {
		return ProtectedResourceMetadata{}, models.ErrOAuthInvalidResource
	}
	return ProtectedResourceMetadata{
		Resource:               resource.Identifier,
		AuthorizationServers:   []string{s.Cfg.Issuer},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        append([]string(nil), resource.Scopes...),
		ResourceName:           resource.DisplayName,
		ResourceSigningAlgValuesSup: []string{
			s.Cfg.SigningAlg,
		},
		JwksURI: s.Cfg.Issuer + "/oauth/jwks",
	}, nil
}
