package theauth

import (
	"context"

	"github.com/glincker/theauth-go/internal/models"
	samlhandlers "github.com/glincker/theauth-go/internal/saml/handlers"
	"github.com/go-chi/chi/v5"
)

// handlers_saml.go: thin forwarders around the extracted
// internal/saml/handlers package. PR E moved the SP-flow endpoints
// (/auth/saml/{connectionId}/{login,acs,metadata}) there; PR F moved
// the per-organization connection CRUD endpoints into the same
// package (crud.go) so root no longer owns any SAML handler bodies.

// samlServiceAdapter implements internal/saml/handlers.Service on top
// of the root *TheAuth, exposing the three SP-flow methods the
// extracted handler needs (BeginLogin, FinishLogin, MetadataXML).
// FinishLogin discards the second return (Session) because the
// handler only writes the cookie.
type samlServiceAdapter struct{ a *TheAuth }

func (s samlServiceAdapter) BeginLogin(ctx context.Context, id models.ULID, relayState string) (string, error) {
	return s.a.BeginSAMLLogin(ctx, id, relayState)
}

func (s samlServiceAdapter) FinishLogin(ctx context.Context, id models.ULID, samlResp, ua, ip string) (string, error) {
	tok, _, err := s.a.FinishSAMLLogin(ctx, id, samlResp, ua, ip)
	return tok, err
}

func (s samlServiceAdapter) MetadataXML(ctx context.Context, id models.ULID) ([]byte, error) {
	return s.a.SAMLMetadataXML(ctx, id)
}

// samlConnectionServiceAdapter implements
// internal/saml/handlers.ConnectionService on top of the root
// *TheAuth, projecting the handler-side input type into the root
// SAMLConnectionInput so the extracted package does not import root.
type samlConnectionServiceAdapter struct{ a *TheAuth }

func (s samlConnectionServiceAdapter) Create(ctx context.Context, in samlhandlers.SAMLConnectionInput) (models.SAMLConnection, error) {
	return s.a.CreateSAMLConnection(ctx, samlConnectionFromHandlers(in))
}

func (s samlConnectionServiceAdapter) Update(ctx context.Context, id models.ULID, in samlhandlers.SAMLConnectionInput) (models.SAMLConnection, error) {
	return s.a.UpdateSAMLConnection(ctx, id, samlConnectionFromHandlers(in))
}

func (s samlConnectionServiceAdapter) Delete(ctx context.Context, id models.ULID) error {
	return s.a.DeleteSAMLConnection(ctx, id)
}

func (s samlConnectionServiceAdapter) ByID(ctx context.Context, id models.ULID) (*models.SAMLConnection, error) {
	return s.a.SAMLConnectionByID(ctx, id)
}

func (s samlConnectionServiceAdapter) List(ctx context.Context, orgID models.ULID) ([]models.SAMLConnection, error) {
	return s.a.ListSAMLConnections(ctx, orgID)
}

func samlConnectionFromHandlers(in samlhandlers.SAMLConnectionInput) SAMLConnectionInput {
	return SAMLConnectionInput{
		OrganizationID: in.OrganizationID,
		IdPEntityID:    in.IdPEntityID,
		IdPSSOURL:      in.IdPSSOURL,
		IdPX509Cert:    in.IdPX509Cert,
		SPEntityID:     in.SPEntityID,
		SPACSURL:       in.SPACSURL,
		AttributeMap:   in.AttributeMap,
	}
}

// newSAMLHandler builds the extracted Handler with both the SP-flow
// and the CRUD-side dependencies attached. Used by both mountSAML
// (SP-flow) and the org-tree subroute (CRUD).
func (a *TheAuth) newSAMLHandler() *samlhandlers.Handler {
	h := samlhandlers.New(
		samlServiceAdapter{a: a},
		samlhandlers.SessionCookieConfig{
			Name:       a.cookieName,
			SecureFlag: a.secureCookie,
			TTL:        a.sessionTTL,
		},
		a.postLoginRedirect,
	)
	h.AttachCRUD(samlConnectionServiceAdapter{a: a}, a.requireOrgRoleHTTP, userFromRequest)
	return h
}

// mountSAML wires the public-facing SAML SP-flow endpoints (login,
// ACS, metadata) via the extracted internal/saml/handlers package.
func (a *TheAuth) mountSAML(r chi.Router) {
	a.newSAMLHandler().Mount(r)
}

// mountSAMLConnectionCRUD mounts the five per-org connection CRUD
// endpoints. Called from mountOrganizations' mountSub callback when
// Config.SAML is non-nil so the route still resolves under
// /auth/orgs/{orgId}/saml/connections.
func (a *TheAuth) mountSAMLConnectionCRUD(r chi.Router) {
	a.newSAMLHandler().MountCRUD(r)
}
