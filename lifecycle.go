package theauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	accounthandlers "github.com/glincker/theauth-go/v2/internal/account"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/session"
	"github.com/glincker/theauth-go/v2/internal/trusteddevice"
	"github.com/go-chi/chi/v5"
)

// accountLifecycle backs sign-in gating, forced password change and trusted device revocation.
// state or devices may be nil.
type accountLifecycle struct {
	state   AccountStateStorage
	devices *trusteddevice.Service
}

// CheckSignin refuses disabled accounts and accounts that must change their password. Storage
// errors fail closed.
func (l *accountLifecycle) CheckSignin(ctx context.Context, userID ULID) error {
	if l.state == nil {
		return nil
	}
	st, err := l.state.AccountStateByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("theauth: account state: %w", err)
	}
	switch {
	case st.DisabledAt != nil:
		return NewError(CodeAccountDisabled, "account is disabled", nil)
	case st.MustChangePassword:
		return NewError(CodePasswordChangeRequired, "password change required, reset your password to continue", nil)
	}
	return nil
}

// PasswordChanged clears the forced-change flag and revokes trusted devices.
func (l *accountLifecycle) PasswordChanged(ctx context.Context, userID ULID) error {
	var errs []error
	if l.state != nil {
		if err := l.state.SetMustChangePassword(ctx, userID, false); err != nil && !errors.Is(err, ErrStorageNotFound) {
			errs = append(errs, fmt.Errorf("clear must change password: %w", err))
		}
	}
	if l.devices != nil {
		if _, err := l.devices.RevokeAll(ctx, userID); err != nil {
			errs = append(errs, fmt.Errorf("revoke trusted devices: %w", err))
		}
	}
	return errors.Join(errs...)
}

// RequireChange flags userID so the next sign-in must change the password.
func (l *accountLifecycle) RequireChange(ctx context.Context, userID ULID) error {
	if l.state == nil {
		return ErrAccountStateDisabled
	}
	return l.state.SetMustChangePassword(ctx, userID, true)
}

// setupLifecycle wires the enabled account lifecycle features. It runs after the session service
// and before password and TOTP.
func (a *TheAuth) setupLifecycle(cfg *Config) error {
	l := &accountLifecycle{}
	if cfg.AccountState {
		st, ok := cfg.storageRaw.(AccountStateStorage)
		if !ok {
			return missingCapability("AccountStateStorage (required by Config.AccountState)")
		}
		l.state = st
		a.sessionSvc.SetAccountGate(l)
	}
	if cfg.AccountDeletion != nil {
		if _, ok := cfg.storageRaw.(AccountDeleteStorage); !ok {
			return missingCapability("AccountDeleteStorage (required by Config.AccountDeletion)")
		}
		if cfg.AccountDeletion.RecentAuthMaxAge < 0 {
			return errors.New("theauth: Config.AccountDeletion.RecentAuthMaxAge must not be negative")
		}
		d := *cfg.AccountDeletion
		if d.RecentAuthMaxAge == 0 {
			d.RecentAuthMaxAge = 10 * time.Minute
		}
		a.deletion = &d
	}
	if err := a.setupSessionPolicy(cfg); err != nil {
		return err
	}
	if cfg.TrustedDevices != nil {
		if cfg.TOTP == nil {
			return errors.New("theauth: Config.TrustedDevices requires Config.TOTP")
		}
		ds, ok := cfg.storageRaw.(TrustedDeviceStorage)
		if !ok {
			return missingCapability("TrustedDeviceStorage (required by Config.TrustedDevices)")
		}
		if cfg.TrustedDevices.TTL < 0 {
			return errors.New("theauth: Config.TrustedDevices.TTL must not be negative")
		}
		svc, err := trusteddevice.New(ds, cfg.EncryptionKey, cfg.TrustedDevices.TTL)
		if err != nil {
			return fmt.Errorf("theauth: Config.TrustedDevices requires Config.EncryptionKey: %w", err)
		}
		l.devices = svc
		a.devices = svc
		a.deviceCookie = cfg.TrustedDevices.CookieName
		if a.deviceCookie == "" {
			a.deviceCookie = trusteddevice.DefaultCookieName
		}
	}
	if l.state != nil || l.devices != nil {
		a.acct = l
	}
	return nil
}

func (a *TheAuth) setupSessionPolicy(cfg *Config) error {
	p := cfg.SessionPolicy
	if p == nil || p.MaxConcurrentSessions == 0 {
		return nil
	}
	if p.MaxConcurrentSessions < 0 {
		return errors.New("theauth: SessionPolicy.MaxConcurrentSessions must not be negative")
	}
	mode := session.OverflowEvictOldest
	switch p.Overflow {
	case "", SessionEvictOldest:
	case SessionReject:
		mode = session.OverflowReject
	default:
		return fmt.Errorf("theauth: unknown SessionPolicy.Overflow %q", p.Overflow)
	}
	if a.sx.mgmt == nil {
		return missingCapability("SessionManagementStorage (required by SessionPolicy.MaxConcurrentSessions)")
	}
	a.sessionSvc.SetCap(session.Cap{Max: p.MaxConcurrentSessions, Mode: mode, Lister: a.sx.mgmt, Revoker: a.storage})
	return nil
}

func (a *TheAuth) passwordChanged(ctx context.Context, userID ULID) {
	if a.acct == nil {
		return
	}
	if err := a.acct.PasswordChanged(ctx, userID); err != nil {
		slog.Error("theauth: account lifecycle after password change failed", "user_id", userID.String(), "err", err.Error())
	}
}

// SetMustChangePassword flags or unflags userID for a forced password change. Setting it also
// revokes the user's sessions. Needs Config.AccountState.
func (a *TheAuth) SetMustChangePassword(ctx context.Context, userID ULID, required bool) error {
	if a.acct == nil || a.acct.state == nil {
		return ErrAccountStateDisabled
	}
	if err := a.acct.state.SetMustChangePassword(ctx, userID, required); err != nil {
		return fmt.Errorf("theauth: set must change password: %w", err)
	}
	if required {
		if err := a.storage.RevokeUserSessions(ctx, userID); err != nil {
			return fmt.Errorf("theauth: set must change password: revoke sessions: %w", err)
		}
		a.EmitAudit(ctx, "password.change_required", TargetRef{Type: "user", ID: userID.String()}, nil)
	}
	return nil
}

// DisableUser blocks sign-in and revokes the user's sessions and API tokens. Needs
// Config.AccountState. EnableUser lifts the block but not the revocations.
func (a *TheAuth) DisableUser(ctx context.Context, userID ULID) error {
	if a.acct == nil || a.acct.state == nil {
		return ErrAccountStateDisabled
	}
	now := time.Now()
	if err := a.acct.state.SetUserDisabledAt(ctx, userID, &now); err != nil {
		return fmt.Errorf("theauth: disable user: %w", err)
	}
	if err := a.storage.RevokeUserSessions(ctx, userID); err != nil {
		return fmt.Errorf("theauth: disable user: revoke sessions: %w", err)
	}
	if ts, ok := a.storageRaw.(APITokenStorage); ok {
		if _, err := ts.RevokeAPITokensByOwner(ctx, userID, now); err != nil {
			return fmt.Errorf("theauth: disable user: revoke api tokens: %w", err)
		}
	}
	if a.devices != nil {
		if _, err := a.devices.RevokeAll(ctx, userID); err != nil {
			return fmt.Errorf("theauth: disable user: revoke trusted devices: %w", err)
		}
	}
	a.EmitAudit(ctx, "account.disabled", TargetRef{Type: "user", ID: userID.String()}, nil)
	return nil
}

// EnableUser lifts a DisableUser block.
func (a *TheAuth) EnableUser(ctx context.Context, userID ULID) error {
	if a.acct == nil || a.acct.state == nil {
		return ErrAccountStateDisabled
	}
	if err := a.acct.state.SetUserDisabledAt(ctx, userID, nil); err != nil {
		return fmt.Errorf("theauth: enable user: %w", err)
	}
	a.EmitAudit(ctx, "account.enabled", TargetRef{Type: "user", ID: userID.String()}, nil)
	return nil
}

// DeleteUser permanently deletes userID and everything owned by them, keeping audit rows with the
// actor cleared. It returns ErrLastOwner when the user is the sole owner of an organization.
// OnAccountDeleted fires after the delete commits.
func (a *TheAuth) DeleteUser(ctx context.Context, userID ULID) error {
	return a.deleteUser(ctx, userID, "admin")
}

func (a *TheAuth) deleteUser(ctx context.Context, userID ULID, reason string) error {
	del, ok := a.storageRaw.(AccountDeleteStorage)
	if !ok {
		return missingCapability("AccountDeleteStorage")
	}
	user, err := a.storage.UserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("theauth: delete user: %w", err)
	}
	if err := a.guardLastOwner(ctx, userID); err != nil {
		return err
	}
	if err := del.DeleteUserCascade(ctx, userID); err != nil {
		return fmt.Errorf("theauth: delete user: %w", err)
	}
	a.EmitAudit(ctx, "account.deleted", TargetRef{Type: "user", ID: userID.String()}, map[string]any{
		"reason":     reason,
		"email_hash": HashEmailForAudit(user.Email),
	})
	a.fireOnAccountDeleted(ctx, user)
	return nil
}

func (a *TheAuth) guardLastOwner(ctx context.Context, userID ULID) error {
	if a.orgsCfg == nil {
		return nil
	}
	orgs, err := a.storage.OrganizationsByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("theauth: delete user: list organizations: %w", err)
	}
	for _, o := range orgs {
		members, err := a.storage.OrganizationMembersByOrg(ctx, o.ID)
		if err != nil {
			return fmt.Errorf("theauth: delete user: list members: %w", err)
		}
		owners, mine := 0, false
		for _, m := range members {
			if m.Role == OrgRoleOwner {
				owners++
				if m.UserID == userID {
					mine = true
				}
			}
		}
		if mine && owners <= 1 {
			return fmt.Errorf("theauth: delete user: organization %s: %w", o.ID, ErrLastOwner)
		}
	}
	return nil
}

func (a *TheAuth) fireOnAccountDeleted(ctx context.Context, user *User) {
	if a.lifecycle.OnAccountDeleted == nil || user == nil {
		return
	}
	runLifecycleHook(ctx, "OnAccountDeleted", a.lifecycle.OnHookError, func() error {
		return a.lifecycle.OnAccountDeleted(ctx, user)
	})
}

func (a *TheAuth) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	if sess == nil {
		writeJSONError(w, http.StatusUnauthorized, CodeInvalidCredentials, "no session")
		return
	}
	if err := a.deleteUser(r.Context(), sess.UserID, "self_service"); err != nil {
		if errors.Is(err, ErrLastOwner) {
			writeJSONError(w, http.StatusConflict, "last_owner", "transfer ownership of your organizations before deleting the account")
			return
		}
		errToHTTP(w, err)
		return
	}
	a.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (a *TheAuth) withSelfDelete(h *accounthandlers.Handler) {
	if a.deletion == nil {
		return
	}
	h.WithSelfDelete(a.handleAccountDelete, a.RequireRecentAuth(a.deletion.RecentAuthMaxAge))
}

// mountAccountDelete registers DELETE /account when AccountDeletion is set and AccountUX is not
// mounting /account itself.
func (a *TheAuth) mountAccountDelete(r chi.Router) {
	if a.deletion == nil || a.accountUX {
		return
	}
	r.With(a.RequireRecentAuth(a.deletion.RecentAuthMaxAge)).Delete("/account", a.handleAccountDelete)
}

// ListTrustedDevices returns the user's live trusted devices, newest first.
func (a *TheAuth) ListTrustedDevices(ctx context.Context, userID ULID) ([]TrustedDeviceInfo, error) {
	if a.devices == nil {
		return nil, errors.New("theauth: Config.TrustedDevices is not enabled")
	}
	rows, err := a.devices.List(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("theauth: list trusted devices: %w", err)
	}
	out := make([]TrustedDeviceInfo, 0, len(rows))
	for _, d := range rows {
		label := d.Label
		if label == "" {
			label = session.DeviceLabel(d.UserAgent)
		}
		out = append(out, TrustedDeviceInfo{
			ID: d.ID, DeviceLabel: label, IPPrefix: session.IPPrefix(d.IP),
			CreatedAt: d.CreatedAt, LastUsedAt: d.LastUsedAt, ExpiresAt: d.ExpiresAt,
		})
	}
	return out, nil
}

// RevokeTrustedDevice revokes one of the user's trusted devices. Unknown, foreign or already
// revoked devices return ErrStorageNotFound.
func (a *TheAuth) RevokeTrustedDevice(ctx context.Context, userID, id ULID) error {
	if a.devices == nil {
		return errors.New("theauth: Config.TrustedDevices is not enabled")
	}
	if err := a.devices.Revoke(ctx, userID, id); err != nil {
		return fmt.Errorf("theauth: revoke trusted device: %w", err)
	}
	a.EmitAudit(ctx, "trusted_device.revoked", TargetRef{Type: "user", ID: userID.String()}, map[string]any{"device_id": id.String()})
	return nil
}

// RevokeTrustedDevices revokes every trusted device of the user and returns how many it revoked.
func (a *TheAuth) RevokeTrustedDevices(ctx context.Context, userID ULID) (int, error) {
	if a.devices == nil {
		return 0, errors.New("theauth: Config.TrustedDevices is not enabled")
	}
	n, err := a.devices.RevokeAll(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("theauth: revoke trusted devices: %w", err)
	}
	a.EmitAudit(ctx, "trusted_device.revoked_all", TargetRef{Type: "user", ID: userID.String()}, map[string]any{"count": n})
	return n, nil
}

func (a *TheAuth) handleTrustedDeviceList(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	list, err := a.ListTrustedDevices(r.Context(), sess.UserID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": list})
}

func (a *TheAuth) handleTrustedDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	id, err := httpx.ParseULIDParam(chi.URLParam(r, "id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "device not found")
		return
	}
	if err := a.RevokeTrustedDevice(r.Context(), sess.UserID, id); err != nil {
		if errors.Is(err, ErrStorageNotFound) {
			writeJSONError(w, http.StatusNotFound, "not_found", "device not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *TheAuth) handleTrustedDeviceRevokeAll(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	n, err := a.RevokeTrustedDevices(r.Context(), sess.UserID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

func (a *TheAuth) mountTrustedDevices(r chi.Router) {
	if a.devices == nil {
		return
	}
	auth := a.RequireAuth()
	r.With(auth).Get("/trusted-devices", a.handleTrustedDeviceList)
	r.With(auth).Delete("/trusted-devices/{id}", a.handleTrustedDeviceRevoke)
	r.With(auth).Delete("/trusted-devices", a.handleTrustedDeviceRevokeAll)
}

func (a *TheAuth) rememberTrustedDevice(ctx context.Context, userID ULID, userAgent, ip string) (string, time.Time, error) {
	if a.devices == nil {
		return "", time.Time{}, errors.New("theauth: Config.TrustedDevices is not enabled")
	}
	val, exp, err := a.devices.Remember(ctx, userID, userAgent, ip)
	if err != nil {
		return "", time.Time{}, err
	}
	a.EmitAudit(ctx, "trusted_device.created", TargetRef{Type: "user", ID: userID.String()}, nil)
	return val, exp, nil
}
