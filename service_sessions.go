package theauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/password"
	"github.com/glincker/theauth-go/internal/session"
	"github.com/glincker/theauth-go/internal/ulid"
)

// CredentialChecker reports whether the upstream credential a session is tied
// to is still valid. It must return ErrCredentialRevoked when the credential
// is revoked, expired or unknown; any other error is treated as transient and
// fails the session check closed.
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
	// TTL is how long a minted link can be exchanged. Defaults to 2m.
	TTL time.Duration
	// CredentialChecker is consulted at mint, at exchange, and on every use
	// of a session that carries a CredentialID. Required.
	CredentialChecker CredentialChecker
}

// Step-up methods accepted by StepUp.
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

// StepUpInput carries the proof for StepUp. Password uses Password, TOTP uses
// Code, passkey uses Challenge (from BeginStepUpPasskey) and Assertion (the
// browser's JSON credential response).
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

// install wires the policy into the session service.
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

// ListSessions returns the user's live sessions, marking currentID, newest
// first. Pending-2FA sessions and idle-expired sessions are omitted.
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

// RevokeOwnedSession revokes one session after confirming it belongs to
// userID. A session owned by someone else reports ErrStorageNotFound so ids
// cannot be probed.
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

// RevokeOtherSessions revokes every live session of userID except keep and
// returns how many it revoked.
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

// RevokeSessionsByCredential revokes every live session tied to credentialID.
// Call it when the upstream credential is revoked to cut sessions at once;
// sessions are also re-checked lazily on every use.
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

// RotateSession issues a fresh token for the same user, UA and IP and revokes
// old. Use it after a privilege change so a token an attacker may hold stops
// working.
func (a *TheAuth) RotateSession(ctx context.Context, old Session) (string, Session, error) {
	user, err := a.storage.UserByID(ctx, old.UserID)
	if err != nil {
		return "", Session{}, fmt.Errorf("theauth: rotate session: load user: %w", err)
	}
	tok, ns, err := a.issueSession(ctx, *user, old.UserAgent, old.IP)
	if err != nil {
		return "", Session{}, fmt.Errorf("theauth: rotate session: issue: %w", err)
	}
	if err := a.storage.RevokeSession(ctx, old.ID); err != nil {
		_ = a.storage.RevokeSession(ctx, ns.ID)
		return "", Session{}, fmt.Errorf("theauth: rotate session: revoke old: %w", err)
	}
	return tok, ns, nil
}

// ChangePassword verifies the current password, sets the new one, revokes all
// of the user's sessions and returns a fresh session token for the caller.
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
	if err := a.storage.RevokeUserSessions(ctx, cur.UserID); err != nil {
		return "", fmt.Errorf("theauth: change password: revoke sessions: %w", err)
	}
	user, err := a.storage.UserByID(ctx, cur.UserID)
	if err != nil {
		return "", fmt.Errorf("theauth: change password: load user: %w", err)
	}
	tok, _, err := a.issueSession(ctx, *user, cur.UserAgent, cur.IP)
	if err != nil {
		return "", fmt.Errorf("theauth: change password: issue session: %w", err)
	}
	a.EmitAudit(ctx, "password.changed", TargetRef{Type: "user", ID: cur.UserID.String()}, nil)
	a.fireOnPasswordChange(ctx, user)
	return tok, nil
}

// StepUp verifies a second proof of identity for the session's user and
// elevates the session for Config.StepUpTTL, returning the elevation expiry.
func (a *TheAuth) StepUp(ctx context.Context, sess *Session, in StepUpInput) (time.Time, error) {
	if a.sx.mgmt == nil {
		return time.Time{}, missingCapability("SessionManagementStorage")
	}
	if err := a.verifyStepUp(ctx, sess, in); err != nil {
		return time.Time{}, err
	}
	until := time.Now().Add(a.sx.stepUpTTL)
	if err := a.sx.mgmt.SetSessionElevatedUntil(ctx, sess.ID, &until); err != nil {
		return time.Time{}, fmt.Errorf("theauth: step-up: elevate session: %w", err)
	}
	a.EmitAudit(ctx, "session.step_up", TargetRef{Type: "session", ID: sess.ID.String()}, map[string]any{"method": in.Method})
	return until, nil
}

var errStepUpMethod = NewError(CodeInvalidCredentials, "unsupported or unavailable step-up method", nil)

func (a *TheAuth) verifyStepUp(ctx context.Context, sess *Session, in StepUpInput) error {
	switch in.Method {
	case StepUpMethodPassword:
		hash, err := a.storage.UserPasswordHashByID(ctx, sess.UserID)
		if err != nil {
			return fmt.Errorf("theauth: step-up: load hash: %w", err)
		}
		ok := false
		if hash != "" {
			var newHash string
			if ok, newHash, err = password.VerifyCredential(in.Password, hash, a.allowLegacyBcrypt); err != nil {
				return fmt.Errorf("theauth: step-up: verify password: %w", err)
			}
			if newHash != "" {
				password.UpgradeHash(ctx, a.storage.SetUserPassword, sess.UserID, newHash)
			}
		}
		if !ok {
			return NewError(CodeInvalidCredentials, "incorrect password", nil)
		}
		return nil
	case StepUpMethodTOTP:
		if a.totpCfg == nil {
			return errStepUpMethod
		}
		return a.totpSvc.CheckCode(ctx, sess.ID, sess.UserID, in.Code)
	case StepUpMethodPasskey:
		if a.webauthnCfg == nil {
			return errStepUpMethod
		}
		// FinishLogin validates the assertion and bumps the sign count; the
		// session it issues is discarded.
		_, issued, err := a.webauthnSvc.FinishLogin(ctx, in.Challenge, bytes.NewReader(in.Assertion), sess.UserAgent, sess.IP)
		if err != nil {
			return err
		}
		if rerr := a.storage.RevokeSession(ctx, issued.ID); rerr != nil {
			slog.Warn("theauth: revoke step-up probe session failed", "session_id", issued.ID.String(), "err", rerr.Error())
		}
		if issued.UserID != sess.UserID {
			return NewError(CodeInvalidCredentials, "passkey belongs to a different user", nil)
		}
		return nil
	}
	return errStepUpMethod
}

// lastAuthAt is when the session's user last proved identity: login time, or
// the latest step-up. Sessions tied to a credential never count their creation.
func (a *TheAuth) lastAuthAt(s *Session) time.Time {
	var t time.Time
	if s.CredentialID == "" {
		t = s.CreatedAt
	}
	if s.ElevatedUntil != nil {
		if e := s.ElevatedUntil.Add(-a.sx.stepUpTTL); e.After(t) {
			t = e
		}
	}
	return t
}

// RequireRecentAuth rejects with 403 auth.recent_auth_required unless the
// session logged in or stepped up within maxAge. It implies RequireAuth.
func (a *TheAuth) RequireRecentAuth(maxAge time.Duration) func(http.Handler) http.Handler {
	auth := a.RequireAuth()
	return func(next http.Handler) http.Handler {
		return auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, _ := SessionFromContext(r.Context())
			if sess == nil || time.Since(a.lastAuthAt(sess)) > maxAge {
				writeProblemJSON(w, http.StatusForbidden, "auth.recent_auth_required", "Recent authentication required, POST /auth/step-up", "")
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// WatchSession re-validates sessionToken every interval and cancels the
// returned context, with the reason as its cause, once it stops validating.
// It fails closed on any error. Checks do not count as user activity. Call the
// cancel func when the stream ends.
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

// WatchSessionMiddleware wraps a streaming handler so the request context is
// cancelled when the caller's session stops validating (see WatchSession).
// Place it after Authn or RequireAuth.
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
	// CredentialID ties the resulting session to an upstream credential that
	// is re-checked on every use. Empty mints an unbound link.
	CredentialID string
	// TTL overrides Config.SessionLinks.TTL when positive.
	TTL time.Duration
	// SessionTTL bounds the resulting session when positive.
	SessionTTL time.Duration
}

// MintSessionLink mints a single-use token that ConsumeSessionLink exchanges
// for a session for in.UserID. The raw token is returned once; only its hash
// is stored. The caller authorizes the mint.
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

// ConsumeSessionLink exchanges a link token for a session token. Every
// failure mode returns ErrSessionLinkInvalid.
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
	tok, sess, err := a.sessionSvc.IssueWith(ctx, *user, session.IssueOptions{
		UserAgent: userAgent, IP: ip, CredentialID: link.CredentialID, TTL: link.SessionTTL,
	})
	if err != nil {
		return "", Session{}, fmt.Errorf("theauth: consume session link: issue session: %w", err)
	}
	a.EmitAudit(ctx, "session.link.consumed", TargetRef{Type: "session", ID: sess.ID.String()}, nil)
	return tok, sess, nil
}
