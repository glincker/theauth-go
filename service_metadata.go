package theauth

import (
	"errors"

	internalas "github.com/glincker/theauth-go/internal/as"
)

// service_metadata.go: thin forwarder for the RFC 8414 authorization
// server metadata document. PR B architecture reorg (2026-06-20) moved
// the implementation into internal/as; the exported document type is
// re-exported as an alias so the v2.0 public surface is unchanged.

// ASMetadata is the JSON document served at
// /.well-known/oauth-authorization-server. Field names and shape follow
// RFC 8414 section 2.
type ASMetadata = internalas.ASMetadata

// ASMetadataDoc builds the metadata document. The result is
// deterministic across calls so handler caching is trivial.
func (a *TheAuth) ASMetadataDoc() (ASMetadata, error) {
	if a.as == nil {
		return ASMetadata{}, errors.New("theauth: authorization server not configured")
	}
	return a.as.ASMetadataDoc()
}
