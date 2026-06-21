package theauth

import (
	"context"

	"github.com/glincker/theauth-go/internal/models"
	scimhandlers "github.com/glincker/theauth-go/internal/scim/handlers"
	"github.com/go-chi/chi/v5"
)

// handlers_scim.go: thin forwarder around the extracted
// internal/scim/handlers package. PR F architecture reorg
// (2026-06-20) moved the 15 SCIM resource endpoints and the 3 token
// CRUD endpoints out of root; the wire helpers and PATCH logic now
// live in internal/scim (wire.go, patch.go). Root keeps a tiny
// service adapter, the audit-emit shim, and a constructor that wires
// everything onto chi via mountSCIM (called by Mount) and
// mountSCIMTokenCRUD (called from mountOrganizations' mountSub).

// scimTokenServiceAdapter implements scimhandlers.TokenService on top
// of the root *TheAuth. The adapter exists so the extracted package
// does not import root.
type scimTokenServiceAdapter struct{ a *TheAuth }

func (s scimTokenServiceAdapter) CreateToken(ctx context.Context, orgID models.ULID, name string) (string, models.SCIMToken, error) {
	return s.a.CreateSCIMToken(ctx, orgID, name)
}

func (s scimTokenServiceAdapter) RevokeToken(ctx context.Context, id models.ULID) error {
	return s.a.RevokeSCIMToken(ctx, id)
}

func (s scimTokenServiceAdapter) ListTokens(ctx context.Context, orgID models.ULID) ([]models.SCIMToken, error) {
	return s.a.ListSCIMTokens(ctx, orgID)
}

// newSCIMHandler builds the extracted Handler with both the resource
// and token-CRUD-side dependencies wired.
func (a *TheAuth) newSCIMHandler() *scimhandlers.Handler {
	maxPage := 0
	if a.scimCfg != nil {
		maxPage = a.scimCfg.MaxPageSize
	}
	return scimhandlers.New(
		a.storage,
		scimTokenServiceAdapter{a: a},
		scimhandlers.Config{
			BaseURL:     a.baseURL,
			MaxPageSize: maxPage,
		},
		a.emitSCIMAuditExternal,
		a.ensureOrgMembership,
		a.requireOrgRoleHTTP,
		userFromRequest,
		scimOrgFromContext,
		scimTokenIDFromContext,
	)
}

// mountSCIM wires the /scim/v2/* resource and discovery endpoints via
// the extracted handler. The scimAuth middleware stays on root because
// it owns the SCIMConfig.RequireHTTPS state and the token lookup;
// passing it in keeps the import direction one-way.
func (a *TheAuth) mountSCIM(r chi.Router) {
	a.newSCIMHandler().Mount(r, a.scimAuth())
}

// mountSCIMTokenCRUD mounts the three /auth/orgs/{orgId}/scim/tokens
// endpoints. Called from mountOrganizations' mountSub callback when
// Config.SCIM is non-nil so the route still resolves under the org
// tree.
func (a *TheAuth) mountSCIMTokenCRUD(r chi.Router) {
	a.newSCIMHandler().MountTokenCRUD(r)
}

// emitSCIMAuditExternal adapts the in-package emitSCIMAudit signature
// to the AuditEmitter callback shape the extracted handler expects:
// it attaches the organization to the audit metadata, sets the
// SCIM-token actor, and forwards to the existing async writer.
func (a *TheAuth) emitSCIMAuditExternal(ctx context.Context, action string, orgID, resourceID, scimTokenID models.ULID, detail string) {
	md := AuditMetadata{OrganizationID: &orgID}
	ctx = WithAuditMetadata(ctx, md)
	meta := map[string]any{"scim_token_id": scimTokenID.String()}
	if detail != "" {
		meta["detail"] = detail
	}
	a.EmitAudit(ctx, action, TargetRef{Type: "user", ID: resourceID.String()}, meta)
}
