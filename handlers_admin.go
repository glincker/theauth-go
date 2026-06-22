package theauth

import (
	"context"
	"net/http"

	adminhandlers "github.com/glincker/theauth-go/internal/admin"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/go-chi/chi/v5"
)

// handlers_admin.go: thin forwarder around the extracted
// internal/admin/handlers package. PR F architecture reorg
// (2026-06-20) moved the 12 /admin/v1 endpoints plus the
// requireOrgMatch middleware there. The agent + delegation admin
// subtree (PR F's other extraction at internal/agent/handlers) is
// wired in via the MountAgents callback supplied below.

// adminRBACAdapter implements adminhandlers.RBACService on top of
// root *TheAuth.
type adminRBACAdapter struct{ a *TheAuth }

func (s adminRBACAdapter) GrantRole(ctx context.Context, actorID, userID, roleID models.ULID) error {
	return s.a.GrantRole(ctx, actorID, userID, roleID)
}

func (s adminRBACAdapter) RevokeRole(ctx context.Context, actorID, userID, roleID models.ULID) error {
	return s.a.RevokeRole(ctx, actorID, userID, roleID)
}

func (s adminRBACAdapter) CreateRole(ctx context.Context, orgID models.ULID, name, description string, permissions []string) (models.Role, error) {
	return s.a.CreateRole(ctx, orgID, name, description, permissions)
}

func (s adminRBACAdapter) UpdateRole(ctx context.Context, roleID models.ULID, name, description string, permissions []string) (models.Role, error) {
	return s.a.UpdateRole(ctx, roleID, name, description, permissions)
}

func (s adminRBACAdapter) DeleteRole(ctx context.Context, roleID models.ULID) error {
	return s.a.DeleteRole(ctx, roleID)
}

// adminAuditAdapter implements adminhandlers.AuditService on top of
// root *TheAuth.
type adminAuditAdapter struct{ a *TheAuth }

func (s adminAuditAdapter) QueryAudit(ctx context.Context, q models.AuditQuery) ([]models.AuditEvent, string, error) {
	return s.a.QueryAudit(ctx, q)
}

func (s adminAuditAdapter) EmitAudit(ctx context.Context, action string, target models.TargetRef, meta map[string]any) {
	s.a.EmitAudit(ctx, action, target, meta)
}

func (s adminAuditAdapter) HashEmailForAudit(email string) string {
	return HashEmailForAudit(email)
}

// mountAdmin wires the /admin/v1 routes via the extracted
// internal/admin/handlers package. Called from Mount when
// Config.Admin is non-nil.
func (a *TheAuth) mountAdmin(r chi.Router) {
	pathPrefix := ""
	if a.adminCfg != nil {
		pathPrefix = a.adminCfg.PathPrefix
	}
	h := adminhandlers.New(
		a.storage,
		adminRBACAdapter{a: a},
		adminAuditAdapter{a: a},
		pathPrefix,
		userFromRequest,
		sessionFromRequest,
	)
	h.Mount(
		r,
		a.RequireAuth(),
		func(permission string) func(http.Handler) http.Handler {
			return a.RequirePermission(permission)
		},
		a.mountAdminAgents,
	)
}
