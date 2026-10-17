package theauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/password"
	"github.com/glincker/theauth-go/v2/internal/session"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/go-chi/chi/v5"
)

// CredentialChecker reports whether the upstream credential a session is tied to is still valid. It
// must return ErrCredentialRevoked when the credential is revoked, expired or unknown; other errors
// fail the session check closed.
type CredentialChecker interface {
	CheckCredential(ctx context.Context, credentialID string) error
}

// CredentialCheckerFunc adapts a function to CredentialChecker.
type CredentialCheckerFunc func(ctx context.Context, credentialID string) error

// CheckCredential calls f.
func (f CredentialCheckerFunc) CheckCredential(ctx context.Context, credentialID string) error {
	return f(ctx, credentialID)
}

// SessionLinksConfig enables programmatic session links.
type SessionLinksConfig struct {
	TTL time.Duration
	// CredentialChecker is consulted when a link is minted, when it is exchanged, and on every use of
	// a session that carries a CredentialID. Required.
	CredentialChecker CredentialChecker
}

const (
	StepUpMethodPassword = "password"
	StepUpMethodTOTP     = "totp"
	StepUpMethodPasskey  = "passkey"
)

// SessionInfo is the end-user view of one session.
type SessionInfo struct {
	ID          ULID      `json:"id"`
	DeviceLabel string    `json:"deviceLabel"`
	IPPrefix    string    `json:"ipPrefix,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	LastSeenAt  time.Time `json:"lastSeenAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Current     bool      `json:"current"`
}

// StepUpInput carries the proof for StepUp: Password, TOTP Code, or a passkey Challenge and Assertion.
type StepUpInput struct {
	Method    string
	Password  string
	Code      string
	Challenge string
	Assertion []byte
}

type sessionExt struct {
	mgmt      SessionManagementStorage
	links     SessionLinkStorage
	linksCfg  *SessionLinksConfig
	stepUpTTL time.Duration
	idle      time.Duration
	touch     time.Duration
}

func applySessionDefaults(cfg *Config) {
	if cfg.SessionTouchInterval == 0 {
		cfg.SessionTouchInterval = time.Minute
	}
	if cfg.StepUpTTL == 0 {
		cfg.StepUpTTL = 5 * time.Minute
	}
	if cfg.SessionLinks != nil && cfg.SessionLinks.TTL == 0 {
		cfg.SessionLinks.TTL = 2 * time.Minute
	}
}

func newSessionExt(cfg *Config) (*sessionExt, error) {
	x := &sessionExt{
		stepUpTTL: cfg.StepUpTTL,
		idle:      cfg.SessionIdleTimeout,
		touch:     cfg.SessionTouchInterval,
		linksCfg:  cfg.SessionLinks,
	}
	x.mgmt, _ = cfg.storageRaw.(SessionManagementStorage)
	x.links, _ = cfg.storageRaw.(SessionLinkStorage)
	if cfg.SessionIdleTimeout < 0 {
		return nil, errors.New("theauth: Config.SessionIdleTimeout must not be negative")
	}
	if cfg.SessionIdleTimeout > 0 {
		if x.mgmt == nil {
			return nil, fmt.Errorf("%w: Config.SessionIdleTimeout requires SessionManagementStorage", ErrStorageMissingCapability)
		}
		if cfg.SessionTouchInterval <= 0 || cfg.SessionTouchInterval >= cfg.SessionIdleTimeout {
			return nil, errors.New("theauth: Config.SessionTouchInterval must be positive and shorter than SessionIdleTimeout")
		}
	}
	if cfg.SessionLinks != nil {
		if x.mgmt == nil {
			return nil, fmt.Errorf("%w: Config.SessionLinks requires SessionManagementStorage", ErrStorageMissingCapability)
		}
		if x.links == nil {
			return nil, fmt.Errorf("%w: Config.SessionLinks requires SessionLinkStorage", ErrStorageMissingCapability)
		}
		if cfg.SessionLinks.CredentialChecker == nil {
			return nil, errors.New("theauth: Config.SessionLinks.CredentialChecker is required")
		}
	}
	return x, nil
}

func (x *sessionExt) install(svc *session.Service) {
	p := session.Policy{IdleTimeout: x.idle}
	if x.mgmt != nil && x.touch > 0 {
		p.Toucher = x.mgmt
		p.TouchInterval = x.touch
	}
	if x.linksCfg != nil {
		p.Credentials = x.linksCfg.CredentialChecker
	}
	svc.SetPolicy(p)
}

// ListSessions returns the user's live sessions, newest first, with currentID marked. Pending-2FA
// and idle sessions are omitted.
func (a *TheAuth) ListSessions(ctx context.Context, userID, currentID ULID) ([]SessionInfo, error) {
	if a.sx.mgmt == nil {
		return nil, missingCapability("SessionManagementStorage")
	}
	rows, err := a.sx.mgmt.ListUserSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("theauth: list sessions: %w", err)
	}
	now := time.Now()
	out := make([]SessionInfo, 0, len(rows))
	for _, s := range rows {
		if s.AuthLevel != "" && s.AuthLevel != AuthLevelFull {
			continue
		}
		last := s.LastSeenAt
		if last.IsZero() {
			last = s.CreatedAt
		}
		if a.sx.idle > 0 && now.Sub(last) >= a.sx.idle {
			continue
		}
		out = append(out, SessionInfo{
			ID:          s.ID,
			DeviceLabel: session.DeviceLabel(s.UserAgent),
			IPPrefix:    session.IPPrefix(s.IP),
			CreatedAt:   s.CreatedAt,
			LastSeenAt:  last,
			ExpiresAt:   s.ExpiresAt,
			Current:     s.ID == currentID,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// RevokeOwnedSession revokes one session after confirming it belongs to userID. Another user's
// session returns ErrStorageNotFound, so ids cannot be probed.
func (a *TheAuth) RevokeOwnedSession(ctx context.Context, userID, sessionID ULID) error {
	s, err := a.storage.SessionByID(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("theauth: load session: %w", err)
	}
	if s.UserID != userID {
		return fmt.Errorf("theauth: load session: %w", ErrStorageNotFound)
	}
	if err := a.storage.RevokeSession(ctx, sessionID); err != nil {
		return fmt.Errorf("theauth: revoke session: %w", err)
	}
	a.EmitAudit(ctx, "session.revoked", TargetRef{Type: "session", ID: sessionID.String()}, nil)
	return nil
}

// RevokeOtherSessions revokes every live session of userID except keep, and returns how many it revoked.
func (a *TheAuth) RevokeOtherSessions(ctx context.Context, userID, keep ULID) (int, error) {
	if a.sx.mgmt == nil {
		return 0, missingCapability("SessionManagementStorage")
	}
	n, err := a.sx.mgmt.RevokeOtherUserSessions(ctx, userID, keep)
	if err != nil {
		return 0, fmt.Errorf("theauth: revoke other sessions: %w", err)
	}
	a.EmitAudit(ctx, "session.revoked_others", TargetRef{Type: "user", ID: userID.String()}, map[string]any{"count": n})
	return n, nil
}

// RevokeSessionsByCredential revokes every live session tied to credentialID, for cutting sessions
// when an upstream credential is revoked. Sessions are also re-checked lazily on use.
func (a *TheAuth) RevokeSessionsByCredential(ctx context.Context, credentialID string) (int, error) {
	if a.sx.mgmt == nil {
		return 0, missingCapability("SessionManagementStorage")
	}
	n, err := a.sx.mgmt.RevokeSessionsByCredential(ctx, credentialID)
	if err != nil {
		return 0, fmt.Errorf("theauth: revoke sessions by credential: %w", err)
	}
	return n, nil
}

// RotateSession issues a fresh token for the same user, UA and IP and revokes the old one. Use it
// after a privilege change.
func (a *TheAuth) RotateSession(ctx context.Context, old Session) (string, Session, error) {
	user, err := a.storage.UserByID(ctx, old.UserID)
	if err != nil {
		return "", Session{}, fmt.Errorf("theauth: rotate session: load user: %w", err)
	}
	// Rotation replaces a session one for one, so it must not trip the concurrent session cap. The
	// replacement keeps the old record and authentication time.
	rctx := session.WithoutLimits(ctx)
	if len(old.AuthMethods) > 0 {
		rctx = models.WithAuthRecord(rctx, old.AuthTime, old.AuthMethods...)
	}
	tok, ns, err := a.issueSession(rctx, *user, old.UserAgent, old.IP)
	if err != nil {
		return "", Session{}, fmt.Errorf("theauth: rotate session: issue: %w", err)
	}
	if err := a.storage.RevokeSession(ctx, old.ID); err != nil {
		_ = a.storage.RevokeSession(ctx, ns.ID)
		return "", Session{}, fmt.Errorf("theauth: rotate session: revoke old: %w", err)
	}
	return tok, ns, nil
}

// ChangePassword verifies the current password, sets the new one, revokes all sessions and returns
// a fresh token.
func (a *TheAuth) ChangePassword(ctx context.Context, cur Session, currentPassword, newPassword string) (string, error) {
	hash, err := a.storage.UserPasswordHashByID(ctx, cur.UserID)
	if err != nil {
		return "", fmt.Errorf("theauth: change password: load hash: %w", err)
	}
	ok := false
	if hash != "" {
		if ok, _, err = password.VerifyCredential(currentPassword, hash, a.allowLegacyBcrypt); err != nil {
			return "", fmt.Errorf("theauth: change password: verify: %w", err)
		}
	}
	if !ok {
		return "", NewError(CodeInvalidCredentials, "current password is incorrect", nil)
	}
	if len(newPassword) < password.MinPasswordLength {
		return "", NewError(CodeWeakPassword, fmt.Sprintf("password must be at least %d characters", password.MinPasswordLength), nil)
	}
	newHash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return "", fmt.Errorf("theauth: change password: hash: %w", err)
	}
	if err := a.storage.SetUserPassword(ctx, cur.UserID, newHash); err != nil {
		return "", fmt.Errorf("theauth: change password: store: %w", err)
	}
	a.passwordChanged(ctx, cur.UserID)
	if err := a.storage.RevokeUserSessions(ctx, cur.UserID); err != nil {
		return "", fmt.Errorf("theauth: change password: revoke sessions: %w", err)
	}
	user, err := a.storage.UserByID(ctx, cur.UserID)
	if err != nil {
		return "", fmt.Errorf("theauth: change password: load user: %w", err)
	}
	tok, _, err := a.issueSession(models.WithAuthMethods(ctx, AMRPassword), *user, cur.UserAgent, cur.IP)
	if err != nil {
		return "", fmt.Errorf("theauth: change password: issue session: %w", err)
	}
	a.EmitAudit(ctx, "password.changed", TargetRef{Type: "user", ID: cur.UserID.String()}, nil)
	a.fireOnPasswordChange(ctx, user)
	return tok, nil
}

// StepUp verifies a second proof of identity for the session's user and elevates the session for
// Config.StepUpTTL.
func (a *TheAuth) StepUp(ctx context.Context, sess *Session, in StepUpInput) (time.Time, error) {
	if a.sx.mgmt == nil {
		return time.Time{}, missingCapability("SessionManagementStorage")
	}
	probe, err := a.verifyStepUp(ctx, sess, in)
	if err != nil {
		return time.Time{}, err
	}
	until := time.Now().Add(a.sx.stepUpTTL)
	if err := a.sx.mgmt.SetSessionElevatedUntil(ctx, sess.ID, &until); err != nil {
		return time.Time{}, fmt.Errorf("theauth: step-up: elevate session: %w", err)
	}
	if err := a.recordStepUpMethods(ctx, sess, in.Method, probe); err != nil {
		return time.Time{}, err
	}
	a.EmitAudit(ctx, "session.step_up", TargetRef{Type: "session", ID: sess.ID.String()}, map[string]any{"method": in.Method})
	return until, nil
}

func stepUpAMR(method string, probe []string) []string {
	switch method {
	case StepUpMethodTOTP:
		return []string{AMROTP}
	case StepUpMethodPasskey:
		if len(probe) > 0 {
			return probe
		}
		return nil
	default:
		return []string{AMRPassword}
	}
}

// recordStepUpMethods appends the completed step-up to the session record and bumps AuthTime. "mfa"
// is added only when the session already has a record of an earlier factor; a legacy session with
// no record gets exactly what was proved.
func (a *TheAuth) recordStepUpMethods(ctx context.Context, sess *Session, method string, probe []string) error {
	if _, ok := a.storage.(SessionAuthStorage); !ok {
		return nil
	}
	add := stepUpAMR(method, probe)
	if len(add) == 0 {
		return nil
	}
	if len(sess.AuthMethods) > 0 && !sess.HasMethod(add[0]) {
		add = append(append([]string(nil), add...), AMRMFA)
	}
	if err := a.RecordSessionAuth(ctx, sess, add...); err != nil {
		return fmt.Errorf("theauth: step-up: record methods: %w", err)
	}
	return nil
}

// RecordSessionAuth appends authentication methods (RFC 8176 values) to the session's record and
// advances AuthTime to now, atomically. Use it from a host-owned second factor. It returns
// ErrStorageMissingCapability without SessionAuthStorage.
func (a *TheAuth) RecordSessionAuth(ctx context.Context, sess *Session, methods ...string) error {
	if _, ok := a.storage.(SessionAuthStorage); !ok {
		return missingCapability("SessionAuthStorage")
	}
	got, at, err := a.sessionSvc.Append(ctx, sess.ID, time.Now(), methods...)
	if err != nil {
		return fmt.Errorf("theauth: record session auth: %w", err)
	}
	if got != nil {
		sess.AuthMethods = got
		sess.AuthTime = at
	}
	return nil
}

var errStepUpMethod = NewError(CodeInvalidCredentials, "unsupported or unavailable step-up method", nil)

func (a *TheAuth) verifyStepUp(ctx context.Context, sess *Session, in StepUpInput) ([]string, error) {
	switch in.Method {
	case StepUpMethodPassword:
		hash, err := a.storage.UserPasswordHashByID(ctx, sess.UserID)
		if err != nil {
			return nil, fmt.Errorf("theauth: step-up: load hash: %w", err)
		}
		ok := false
		if hash != "" {
			var newHash string
			if ok, newHash, err = password.VerifyCredential(in.Password, hash, a.allowLegacyBcrypt); err != nil {
				return nil, fmt.Errorf("theauth: step-up: verify password: %w", err)
			}
			if newHash != "" {
				password.UpgradeAndNotify(ctx, a.storage.SetUserPassword, a.onLegacyHash, sess.UserID, newHash)
			}
		}
		if !ok {
			return nil, NewError(CodeInvalidCredentials, "incorrect password", nil)
		}
		return nil, nil
	case StepUpMethodTOTP:
		if a.totpCfg == nil {
			return nil, errStepUpMethod
		}
		return nil, a.totpSvc.CheckCode(ctx, sess.ID, sess.UserID, in.Code)
	case StepUpMethodPasskey:
		if a.webauthnCfg == nil {
			return nil, errStepUpMethod
		}
		_, issued, err := a.webauthnSvc.FinishLogin(session.WithoutLimits(ctx), in.Challenge, bytes.NewReader(in.Assertion), sess.UserAgent, sess.IP)
		if err != nil {
			return nil, err
		}
		if rerr := a.storage.RevokeSession(ctx, issued.ID); rerr != nil {
			slog.Warn("theauth: revoke step-up probe session failed", "session_id", issued.ID.String(), "err", rerr.Error())
		}
		if issued.UserID != sess.UserID {
			return nil, NewError(CodeInvalidCredentials, "passkey belongs to a different user", nil)
		}
		return issued.AuthMethods, nil
	}
	return nil, errStepUpMethod
}

// lastAuthAt is when the session's user last proved identity. Sessions tied to a credential never
// count their creation.
func (a *TheAuth) lastAuthAt(s *Session) time.Time {
	t := s.AuthTime
	if s.CredentialID == "" && s.CreatedAt.After(t) {
		t = s.CreatedAt
	}
	if s.ElevatedUntil != nil {
		if e := s.ElevatedUntil.Add(-a.sx.stepUpTTL); e.After(t) {
			t = e
		}
	}
	return t
}

// RequireRecentAuth rejects with 403 auth.recent_auth_required unless the session logged in or
// stepped up within maxAge.
func (a *TheAuth) RequireRecentAuth(maxAge time.Duration) func(http.Handler) http.Handler {
	auth := a.RequireAuth()
	return func(next http.Handler) http.Handler {
		return auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, _ := SessionFromContext(r.Context())
			if sess == nil || time.Since(a.lastAuthAt(sess)) > maxAge {
				a.problem(w, r, http.StatusForbidden, "auth.recent_auth_required", "Recent authentication required, POST "+a.pathPrefix+"/step-up", "")
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// WatchSession re-validates sessionToken every interval and cancels the returned context, with the
// reason as cause, once it stops validating. It fails closed on errors. Checks do not count as user
// activity.
func (a *TheAuth) WatchSession(ctx context.Context, sessionToken string, interval time.Duration) (context.Context, context.CancelCauseFunc) {
	ctx, cancel := context.WithCancelCause(ctx)
	if interval <= 0 {
		cancel(errors.New("theauth: WatchSession interval must be positive"))
		return ctx, cancel
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, _, err := a.sessionSvc.Check(ctx, sessionToken); err != nil {
					cancel(fmt.Errorf("theauth: session no longer valid: %w", err))
					return
				}
			}
		}
	}()
	return ctx, cancel
}

// WatchSessionMiddleware wraps a streaming handler so the request context is cancelled when the
// caller's session stops validating (see WatchSession).
func (a *TheAuth) WatchSessionMiddleware(interval time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(a.cookieName)
			if err != nil || c.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			ctx, cancel := a.WatchSession(r.Context(), c.Value, interval)
			defer cancel(nil)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// MintSessionLinkInput describes a session link to mint.
type MintSessionLinkInput struct {
	UserID ULID
	// CredentialID binds the session to an upstream credential that is re-checked on every use. Empty
	// mints an unbound link.
	CredentialID string
	TTL          time.Duration
	SessionTTL   time.Duration
}

// MintSessionLink mints a single-use token that ConsumeSessionLink exchanges for a session. Only
// its hash is stored.
func (a *TheAuth) MintSessionLink(ctx context.Context, in MintSessionLinkInput) (string, SessionLink, error) {
	if a.sx.linksCfg == nil {
		return "", SessionLink{}, errors.New("theauth: session links are not enabled")
	}
	if _, err := a.storage.UserByID(ctx, in.UserID); err != nil {
		return "", SessionLink{}, fmt.Errorf("theauth: mint session link: load user: %w", err)
	}
	if in.CredentialID != "" {
		if err := a.sx.linksCfg.CredentialChecker.CheckCredential(ctx, in.CredentialID); err != nil {
			return "", SessionLink{}, fmt.Errorf("theauth: mint session link: check credential: %w", err)
		}
	}
	tok, err := crypto.NewToken()
	if err != nil {
		return "", SessionLink{}, fmt.Errorf("theauth: mint session link: token: %w", err)
	}
	ttl := a.sx.linksCfg.TTL
	if in.TTL > 0 {
		ttl = in.TTL
	}
	now := time.Now()
	link := SessionLink{
		ID:           ulid.New(),
		UserID:       in.UserID,
		TokenHash:    crypto.HashToken(tok),
		CredentialID: in.CredentialID,
		SessionTTL:   in.SessionTTL,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
	}
	if err := a.sx.links.CreateSessionLink(ctx, link); err != nil {
		return "", SessionLink{}, fmt.Errorf("theauth: mint session link: store: %w", err)
	}
	a.EmitAudit(ctx, "session.link.minted", TargetRef{Type: "user", ID: in.UserID.String()}, map[string]any{"credential_bound": in.CredentialID != ""})
	return tok, link, nil
}

// ConsumeSessionLink exchanges a link token for a session token. Every failure returns ErrSessionLinkInvalid.
func (a *TheAuth) ConsumeSessionLink(ctx context.Context, token, userAgent, ip string) (string, Session, error) {
	if a.sx.linksCfg == nil {
		return "", Session{}, ErrSessionLinkInvalid
	}
	link, err := a.sx.links.ConsumeSessionLink(ctx, crypto.HashToken(token), time.Now())
	if errors.Is(err, ErrStorageNotFound) {
		return "", Session{}, ErrSessionLinkInvalid
	}
	if err != nil {
		return "", Session{}, fmt.Errorf("theauth: consume session link: %w", err)
	}
	if link.CredentialID != "" {
		if err := a.sx.linksCfg.CredentialChecker.CheckCredential(ctx, link.CredentialID); err != nil {
			if errors.Is(err, ErrCredentialRevoked) {
				return "", Session{}, ErrSessionLinkInvalid
			}
			return "", Session{}, fmt.Errorf("theauth: consume session link: check credential: %w", err)
		}
	}
	user, err := a.storage.UserByID(ctx, link.UserID)
	if err != nil {
		return "", Session{}, ErrSessionLinkInvalid
	}
	// Session links are not interactive sign-ins, so no auth record or AuthTime is written.
	tok, sess, err := a.sessionSvc.IssueWith(models.WithAuthRecord(ctx, time.Time{}), *user, session.IssueOptions{
		UserAgent: userAgent, IP: ip, CredentialID: link.CredentialID, TTL: link.SessionTTL,
	})
	if err != nil {
		return "", Session{}, fmt.Errorf("theauth: consume session link: issue session: %w", err)
	}
	a.EmitAudit(ctx, "session.link.consumed", TargetRef{Type: "session", ID: sess.ID.String()}, nil)
	return tok, sess, nil
}

const sessionBodyLimit = 1 << 16

func (a *TheAuth) mountSessionManagement(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	auth := a.RequireAuth()
	if a.sx.mgmt != nil {
		r.With(auth).Get("/sessions", a.handleSessionList)
		r.With(auth).Delete("/sessions/{id}", a.handleSessionRevokeByID)
		r.With(auth).Post("/sessions/revoke-others", a.handleSessionRevokeOthers)
		r.With(auth, ipLimit).Post("/step-up", a.handleStepUp)
		if a.webauthnCfg != nil {
			r.With(auth, ipLimit).Post("/step-up/passkey/begin", a.handleStepUpPasskeyBegin)
		}
	}
	r.With(auth, ipLimit).Post("/password/change", a.handlePasswordChange)
	a.mountTrustedDevices(r)
	if a.sx.linksCfg != nil {
		r.With(ipLimit).Post("/session-link/consume", a.handleSessionLinkConsume)
	}
}

func (a *TheAuth) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(a.sessionTTL),
	})
}

func (a *TheAuth) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeSessionBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, sessionBodyLimit)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "invalid request body")
		return false
	}
	return true
}

func (a *TheAuth) handleSessionList(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	list, err := a.ListSessions(r.Context(), sess.UserID, sess.ID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

func (a *TheAuth) handleSessionRevokeByID(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	id, err := httpx.ParseULIDParam(chi.URLParam(r, "id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	if err := a.RevokeOwnedSession(r.Context(), sess.UserID, id); err != nil {
		if errors.Is(err, ErrStorageNotFound) {
			writeJSONError(w, http.StatusNotFound, "not_found", "session not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if id == sess.ID {
		a.clearSessionCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *TheAuth) handleSessionRevokeOthers(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	n, err := a.RevokeOtherSessions(r.Context(), sess.UserID, sess.ID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

func (a *TheAuth) handleStepUp(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	var body struct {
		Method    string          `json:"method"`
		Password  string          `json:"password"`
		Code      string          `json:"code"`
		Challenge string          `json:"challenge"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if !decodeSessionBody(w, r, &body) {
		return
	}
	until, err := a.StepUp(r.Context(), sess, StepUpInput{
		Method: body.Method, Password: body.Password, Code: body.Code,
		Challenge: body.Challenge, Assertion: body.Assertion,
	})
	if err != nil {
		if errors.Is(err, ErrStorageMissingCapability) {
			writeJSONError(w, http.StatusNotImplemented, "not_implemented", "step-up is not supported by this storage")
			return
		}
		errToHTTP(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"elevatedUntil": until})
}

func (a *TheAuth) handleStepUpPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	assertion, challenge, err := a.webauthnSvc.BeginLogin(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": assertion, "challenge": challenge})
}

func (a *TheAuth) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFromContext(r.Context())
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if !decodeSessionBody(w, r, &body) {
		return
	}
	tok, err := a.ChangePassword(r.Context(), *sess, body.CurrentPassword, body.NewPassword)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	a.setSessionCookie(w, tok)
	w.WriteHeader(http.StatusNoContent)
}

func (a *TheAuth) handleSessionLinkConsume(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if !decodeSessionBody(w, r, &body) {
		return
	}
	if body.Token == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "token required")
		return
	}
	tok, _, err := a.ConsumeSessionLink(r.Context(), body.Token, r.UserAgent(), extractClientIPTrusting(r, a.trustedProxies))
	if err != nil {
		if errors.Is(err, ErrSessionLinkInvalid) {
			writeJSONError(w, http.StatusUnauthorized, "session_link_invalid", "invalid or expired session link")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	a.setSessionCookie(w, tok)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
