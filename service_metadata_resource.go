package theauth

import (
	"errors"

	internalas "github.com/glincker/theauth-go/internal/as"
)

// service_metadata_resource.go: thin forwarder for the RFC 9728 OAuth
// 2.0 Protected Resource Metadata document. PR B architecture reorg
// (2026-06-20) moved the implementation into internal/as; the exported
// document type is re-exported as an alias so the v2.0 public surface
// is unchanged.

// ProtectedResourceMetadata is the JSON document mandated by RFC 9728.
type ProtectedResourceMetadata = internalas.ProtectedResourceMetadata

// ProtectedResourceMetadataDoc builds the RFC 9728 document for the
// resource matching the supplied identifier. Returns an error when the
// identifier is not one of the configured resources.
func (a *TheAuth) ProtectedResourceMetadataDoc(resourceID string) (ProtectedResourceMetadata, error) {
	if a.as == nil {
		return ProtectedResourceMetadata{}, errors.New("theauth: authorization server not configured")
	}
	return a.as.ProtectedResourceMetadataDoc(resourceID)
}
