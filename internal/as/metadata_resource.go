package as

import (
	"errors"

	"github.com/glincker/theauth-go/internal/models"
)

// metadata_resource.go: RFC 9728 OAuth 2.0 Protected Resource Metadata.
//
// Resource servers (MCP servers using the mcpresource SDK) need a
// discovery document so a fresh client can find the AS that mints tokens
// for them. The AS exposes one document per configured
// ProtectedResource; the path includes the resource identifier path so
// multiple resources can co-exist on the same origin.

// ProtectedResourceMetadata is the JSON document mandated by RFC 9728.
// Only the fields the spec marks REQUIRED + the most-used OPTIONAL ones
// are declared; omitted fields fall away via omitempty so a strict
// parser stays happy.
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

// ProtectedResourceMetadataDoc builds the RFC 9728 document for the
// resource matching the supplied identifier. Returns an error when the
// identifier is not one of the configured resources.
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
