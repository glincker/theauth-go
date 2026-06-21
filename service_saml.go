package theauth

import (
	"context"
	"errors"

	internalsaml "github.com/glincker/theauth-go/internal/saml"
)

// SAML forwarders. PR D architecture reorg (2026-06-20) moved the
// implementations to internal/saml; the public CreateSAMLConnection /
// UpdateSAMLConnection / DeleteSAMLConnection / SAMLConnectionByID /
// ListSAMLConnections / BeginSAMLLogin / FinishSAMLLogin /
// SAMLMetadataXML entry points kept their exact signatures so callers in
// this package (handlers_saml) continue to compile unchanged.

// SAMLConnectionInput is the consumer-facing payload for create / update.
// Mirrors internal/saml.SAMLConnectionInput field-for-field so the public
// type is unchanged.
type SAMLConnectionInput struct {
	OrganizationID ULID
	IdPEntityID    string
	IdPSSOURL      string
	IdPX509Cert    string
	SPEntityID     string
	SPACSURL       string
	AttributeMap   SAMLAttributeMap
}

// toInternal projects the root-facing input type into the internal one.
// Mirror-shape; reuses the same field set.
func (in SAMLConnectionInput) toInternal() internalsaml.SAMLConnectionInput {
	return internalsaml.SAMLConnectionInput{
		OrganizationID: in.OrganizationID,
		IdPEntityID:    in.IdPEntityID,
		IdPSSOURL:      in.IdPSSOURL,
		IdPX509Cert:    in.IdPX509Cert,
		SPEntityID:     in.SPEntityID,
		SPACSURL:       in.SPACSURL,
		AttributeMap:   in.AttributeMap,
	}
}

// CreateSAMLConnection inserts a fresh saml_connections row.
func (a *TheAuth) CreateSAMLConnection(ctx context.Context, in SAMLConnectionInput) (SAMLConnection, error) {
	return a.samlSvc.CreateConnection(ctx, in.toInternal())
}

// UpdateSAMLConnection rewrites an existing connection in place.
func (a *TheAuth) UpdateSAMLConnection(ctx context.Context, id ULID, in SAMLConnectionInput) (SAMLConnection, error) {
	return a.samlSvc.UpdateConnection(ctx, id, in.toInternal())
}

// DeleteSAMLConnection removes the connection + cascades its identities.
func (a *TheAuth) DeleteSAMLConnection(ctx context.Context, id ULID) error {
	return a.samlSvc.DeleteConnection(ctx, id)
}

// SAMLConnectionByID looks up one connection.
func (a *TheAuth) SAMLConnectionByID(ctx context.Context, id ULID) (*SAMLConnection, error) {
	return a.samlSvc.ConnectionByID(ctx, id)
}

// ListSAMLConnections returns every connection for one organization.
func (a *TheAuth) ListSAMLConnections(ctx context.Context, orgID ULID) ([]SAMLConnection, error) {
	return a.samlSvc.ListConnections(ctx, orgID)
}

// BeginSAMLLogin returns the redirect URL for an SP-initiated SSO.
func (a *TheAuth) BeginSAMLLogin(ctx context.Context, connectionID ULID, relayState string) (string, error) {
	return a.samlSvc.BeginLogin(ctx, connectionID, relayState)
}

// FinishSAMLLogin validates an inbound SAMLResponse, runs find-or-create,
// issues a session, and returns its token.
func (a *TheAuth) FinishSAMLLogin(ctx context.Context, connectionID ULID, samlResponseB64 string, ua, ip string) (string, Session, error) {
	return a.samlSvc.FinishLogin(ctx, connectionID, samlResponseB64, ua, ip)
}

// SAMLMetadataXML serialises the per-connection SP metadata as XML.
func (a *TheAuth) SAMLMetadataXML(ctx context.Context, connectionID ULID) ([]byte, error) {
	return a.samlSvc.MetadataXML(ctx, connectionID)
}

// ensureOrgMembership upserts a "member" role row when the user is not
// already a member of the supplied organization. Used by the SCIM handler
// when an idempotent POST should re-enable a soft-deleted member. The
// SAML service has its own copy because internal/saml owns its own
// Storage interface; keeping this small helper on root means the SCIM
// handler does not need to import internal/saml.
func (a *TheAuth) ensureOrgMembership(ctx context.Context, orgID, userID ULID) error {
	_, err := a.storage.OrganizationMemberRole(ctx, orgID, userID)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrStorageNotFound) {
		return err
	}
	return a.storage.UpsertOrganizationMember(ctx, OrganizationMember{
		OrganizationID: orgID,
		UserID:         userID,
		Role:           OrgRoleMember,
	})
}
