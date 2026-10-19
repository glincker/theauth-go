package theauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/internal/agent"
	"github.com/glincker/theauth-go/v2/internal/apitokens"
	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/emailnorm"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/models"
	internaloauth "github.com/glincker/theauth-go/v2/internal/oauth"
	"github.com/glincker/theauth-go/v2/internal/password"
	internalsaml "github.com/glincker/theauth-go/v2/internal/saml"
	"github.com/glincker/theauth-go/v2/internal/totp"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/go-webauthn/webauthn/protocol"
)

// coalesceLifecycleHooks returns the consumer's LifecycleHooks, or a zero value when nil so dispatch sites
// need no nil check on the bundle. Individual fields may still be nil; the fireOn* helpers handle that.
func coalesceLifecycleHooks(h *LifecycleHooks) *LifecycleHooks {
	if h == nil {
		return &LifecycleHooks{}
	}
	return h
}

// runLifecycleHook is the panic-safe runner behind every fireOn* helper. Errors are logged at Warn and panics
// at Error; both are also reported to onErr. Hooks run after the action committed and never fail it.
func runLifecycleHook(ctx context.Context, name string, onErr func(context.Context, string, error), fn func() error) {
	if fn == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			slog.ErrorContext(ctx, "theauth: lifecycle hook panicked", "hook", name, "panic", r)
			reportHookError(ctx, name, onErr, fmt.Errorf("theauth: lifecycle hook %s panicked: %v", name, r))
		}
	}()
	if err := fn(); err != nil {
		slog.WarnContext(ctx, "theauth: lifecycle hook returned error", "hook", name, "err", err.Error())
		reportHookError(ctx, name, onErr, err)
	}
}

// reportHookError calls the host's OnHookError, shielding the request from a panic inside it.
func reportHookError(ctx context.Context, name string, onErr func(context.Context, string, error), err error) {
	if onErr == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			slog.ErrorContext(ctx, "theauth: OnHookError callback panicked", "hook", name, "panic", r)
		}
	}()
	onErr(ctx, name, err)
}

// fireOnSignup dispatches LifecycleHooks.OnSignup.
func (a *TheAuth) fireOnSignup(ctx context.Context, user *User, method SignupMethod) {
	if a.lifecycle.OnSignup == nil || user == nil {
		return
	}
	runLifecycleHook(ctx, "OnSignup", a.lifecycle.OnHookError, func() error {
		return a.lifecycle.OnSignup(ctx, user, method)
	})
}

// fireOnSignin dispatches LifecycleHooks.OnSignin.
func (a *TheAuth) fireOnSignin(ctx context.Context, user *User, sess *Session) {
	if a.lifecycle.OnSignin == nil || user == nil || sess == nil {
		return
	}
	runLifecycleHook(ctx, "OnSignin", a.lifecycle.OnHookError, func() error {
		return a.lifecycle.OnSignin(ctx, user, sess)
	})
}

// fireOnSigninForUserID loads the user, then dispatches OnSignin. Used by paths that return a session but not
// the user row (passkey, SAML, TOTP). Skips the read when no hook is set.
func (a *TheAuth) fireOnSigninForUserID(ctx context.Context, userID ULID, sess *Session) {
	if a.lifecycle.OnSignin == nil {
		return
	}
	user, err := a.storage.UserByID(ctx, userID)
	if err != nil || user == nil {
		return
	}
	a.fireOnSignin(ctx, user, sess)
}

func (a *TheAuth) fireOnPasswordChange(ctx context.Context, user *User) {
	if a.lifecycle.OnPasswordChange == nil || user == nil {
		return
	}
	runLifecycleHook(ctx, "OnPasswordChange", a.lifecycle.OnHookError, func() error {
		return a.lifecycle.OnPasswordChange(ctx, user)
	})
}

func (a *TheAuth) fireOnMFAEnabled(ctx context.Context, user *User, kind MFAKind) {
	if a.lifecycle.OnMFAEnabled == nil || user == nil {
		return
	}
	runLifecycleHook(ctx, "OnMFAEnabled", a.lifecycle.OnHookError, func() error {
		return a.lifecycle.OnMFAEnabled(ctx, user, kind)
	})
}

func (a *TheAuth) fireOnOrgSwitch(ctx context.Context, user *User, orgID string) {
	if a.lifecycle.OnOrgSwitch == nil || user == nil {
		return
	}
	runLifecycleHook(ctx, "OnOrgSwitch", a.lifecycle.OnHookError, func() error {
		return a.lifecycle.OnOrgSwitch(ctx, user, orgID)
	})
}

// UserByID returns (nil, ErrNotFound) when the user does not exist. It spares consumers from
// reaching into storage.
func (a *TheAuth) UserByID(ctx context.Context, id ULID) (*User, error) {
	return a.storage.UserByID(ctx, id)
}

// ErrAuthorizationServerNotConfigured is returned by authorization-server methods when
// Config.AuthorizationServer was not set at New time.
var ErrAuthorizationServerNotConfigured = errors.New("theauth: authorization server not configured")

// MinPasswordLength is enforced at the library level (NIST 2024 baseline).
const MinPasswordLength = password.MinPasswordLength

// PasswordResetTTL is how long a reset token stays valid after issuance.
const PasswordResetTTL = password.PasswordResetTTL

// SigninStep mirrors the v0.5 step indicator returned by signinWithPassword.
type SigninStep = password.SigninStep

const (
	SigninStepFull         = password.SigninStepFull
	SigninStepTOTPRequired = password.SigninStepTOTPRequired
)

// EnrollTOTPResult is returned by BeginTOTPEnrollment for the caller to render.
type EnrollTOTPResult = totp.EnrollResult

// AuditMetadata is an optional bundle attached to a context to override the auto-derived actor,
// org, IP and UA.
type AuditMetadata = audit.AuditMetadata

// WithAuditMetadata attaches an AuditMetadata to ctx; EmitAudit reads it.
func WithAuditMetadata(ctx context.Context, md AuditMetadata) context.Context {
	return audit.WithAuditMetadata(ctx, md)
}

// issueSession mints an opaque token, persists its sha256 hash on a new Session row, and returns
// the raw token.
func (a *TheAuth) issueSession(ctx context.Context, user User, userAgent, ip string) (token string, sess Session, err error) {
	return a.sessionSvc.Issue(ctx, user, userAgent, ip)
}

// validateSession resolves a token by its hash and returns the session and user. It returns
// ErrInvalidToken for unknown tokens and ErrSessionExpired for expired or revoked sessions.
func (a *TheAuth) validateSession(ctx context.Context, token string) (*Session, *User, error) {
	return a.sessionSvc.Validate(ctx, token)
}

// IssueSessionByUserID mints a full session for a user without an existing session token (used after OTP
// verification in the account-linking flow).
func (a *TheAuth) IssueSessionByUserID(ctx context.Context, userID ULID, userAgent, ip string) (string, error) {
	u, err := a.UserByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("theauth: user not found for session: %w", err)
	}
	tok, _, err := a.issueSession(ctx, *u, userAgent, ip)
	return tok, err
}

// LinkOAuthProviderBySession links an OAuth provider to the user behind sessionToken, for the post-OTP
// account-linking flow.
func (a *TheAuth) LinkOAuthProviderBySession(
	ctx context.Context,
	sessionToken, providerName, providerUserID string,
	accessTokenEnc, refreshTokenEnc []byte,
	expiresAt *time.Time,
	scope string,
) error {
	return a.identityLinkSvc.LinkOAuthToCurrentUser(
		ctx, sessionToken, providerName, providerUserID,
		accessTokenEnc, refreshTokenEnc, expiresAt, scope,
	)
}

// UnlinkOAuthProvider removes a provider from the current user's linked accounts. It returns
// ErrLastAuthMethod when that provider is the only sign-in method.
func (a *TheAuth) UnlinkOAuthProvider(ctx context.Context, sessionToken, provider string) error {
	return a.identityLinkSvc.UnlinkOAuthProvider(ctx, sessionToken, provider)
}

// requestMagicLink mints a magic-link token and emails the raw token. The raw token only ever
// appears in the inbox.
func (a *TheAuth) requestMagicLink(ctx context.Context, emailAddr string) error {
	return a.magicSvc.Request(ctx, emailAddr)
}

// requestMagicLinkForTest is the test seam: requestMagicLink that also returns the raw token.
// Production never calls it.
func (a *TheAuth) requestMagicLinkForTest(ctx context.Context, emailAddr string) (string, error) {
	return a.magicSvc.RequestForTest(ctx, emailAddr)
}

// consumeMagicLink validates the single-use token, finds or creates the user, marks the email
// verified, and issues a session. OnSignup fires only when the user row was created here; OnSignin
// fires for the new session.
func (a *TheAuth) consumeMagicLink(ctx context.Context, token string) (sessionToken string, user *User, err error) {
	sessionToken, user, created, err := a.magicSvc.Consume(ctx, token)
	if err != nil {
		return sessionToken, user, err
	}
	if created {
		a.autoProvisionPersonalOrg(ctx, user, sessionToken)
		a.fireOnSignup(ctx, user, SignupMethodMagicLink)
	}
	if sess := a.sessionFromToken(ctx, sessionToken); sess != nil {
		a.fireOnSignin(ctx, user, sess)
	}
	return sessionToken, user, nil
}

// validateEmail exposes password.ValidateEmail for the fuzz seam in internal/testhooks.
func validateEmail(raw string) (string, error) {
	return password.ValidateEmail(raw)
}

// signupWithPassword creates a user with email and password credentials and issues a session. Hook errors are
// logged and never fail the request; the user already exists.
func (a *TheAuth) signupWithPassword(ctx context.Context, emailAddr, pw string) (*User, string, error) {
	user, token, err := a.passwordSvc.Signup(ctx, emailAddr, pw)
	if err != nil {
		return user, token, err
	}
	a.autoProvisionPersonalOrg(ctx, user, token)
	a.fireOnSignup(ctx, user, SignupMethodPassword)
	return user, token, nil
}

// signinWithPassword verifies credentials and issues a session. OnSignin fires only for a full
// sign-in, not for a pending_2fa step; the TOTP or recovery-code step fires it when it completes
// the session.
func (a *TheAuth) signinWithPassword(ctx context.Context, emailAddr, pw, userAgent, ip string) (string, *User, SigninStep, error) {
	token, user, step, err := a.passwordSvc.Signin(ctx, emailAddr, pw, userAgent, ip)
	if err != nil || step != SigninStepFull || user == nil {
		return token, user, step, err
	}
	if sess := a.sessionFromToken(ctx, token); sess != nil {
		a.fireOnSignin(ctx, user, sess)
	}
	return token, user, step, nil
}

// sessionFromToken resolves a just-issued token to its Session row for hook dispatch. It returns
// nil on failure: missing a hook is preferable to failing a sign-in that already succeeded.
func (a *TheAuth) sessionFromToken(ctx context.Context, token string) *Session {
	if token == "" {
		return nil
	}
	sess, _, err := a.validateSession(ctx, token)
	if err != nil {
		return nil
	}
	return sess
}

// requestPasswordResetForTest returns the raw token when one is minted, or "" when the email is unknown.
func (a *TheAuth) requestPasswordResetForTest(ctx context.Context, emailAddr string) (string, error) {
	return a.passwordSvc.RequestResetForTest(ctx, emailAddr)
}

// resetPassword consumes a reset token, updates the password, and revokes all sessions.
// OnPasswordChange fires on success.
func (a *TheAuth) resetPassword(ctx context.Context, token, newPassword string) error {
	userID, err := a.passwordSvc.Reset(ctx, token, newPassword)
	if err != nil {
		return err
	}
	if user, uerr := a.storage.UserByID(ctx, userID); uerr == nil {
		a.fireOnPasswordChange(ctx, user)
	}
	return nil
}

// BeginTOTPEnrollment returns a fresh shared secret and otpauth URL. The secret is shown exactly once.
func (a *TheAuth) BeginTOTPEnrollment(ctx context.Context, userID ULID, accountName string) (EnrollTOTPResult, error) {
	return a.totpSvc.BeginEnrollment(ctx, userID, accountName)
}

// FinishTOTPEnrollment confirms the pending secret with one code and returns the recovery codes. OnMFAEnabled
// fires on success.
func (a *TheAuth) FinishTOTPEnrollment(ctx context.Context, userID ULID, enrollmentID, code string) ([]string, error) {
	codes, err := a.totpSvc.FinishEnrollment(ctx, userID, enrollmentID, code)
	if err != nil {
		return codes, err
	}
	if user, uerr := a.storage.UserByID(ctx, userID); uerr == nil {
		a.fireOnMFAEnabled(ctx, user, MFAKindTOTP)
	}
	return codes, nil
}

// IssuePending2FA mints a short-lived session at AuthLevelPending2FA.
func (a *TheAuth) IssuePending2FA(ctx context.Context, userID ULID, ua, ip string) (string, Session, error) {
	return a.totpSvc.IssuePending2FA(ctx, userID, ua, ip)
}

// VerifyTOTP upgrades the pending session to a full one. OnSignin fires here: this is the moment a password
// sign-in held at pending_2fa becomes a full session.
func (a *TheAuth) VerifyTOTP(ctx context.Context, pendingSessionToken, code string) (string, Session, error) {
	token, sess, err := a.totpSvc.Verify(ctx, pendingSessionToken, code)
	if err != nil {
		return token, sess, err
	}
	a.fireOnSigninForUserID(ctx, sess.UserID, &sess)
	return token, sess, nil
}

// ConsumeRecoveryCode upgrades a pending session by consuming one unused recovery code. OnSignin
// fires as for VerifyTOTP.
func (a *TheAuth) ConsumeRecoveryCode(ctx context.Context, pendingSessionToken, code string) (string, Session, error) {
	token, sess, err := a.totpSvc.ConsumeRecoveryCode(ctx, pendingSessionToken, code)
	if err != nil {
		return token, sess, err
	}
	a.fireOnSigninForUserID(ctx, sess.UserID, &sess)
	return token, sess, nil
}

// BeginPasskeyRegistration starts a WebAuthn credential creation ceremony. The returned challenge
// token goes in a short-lived cookie.
func (a *TheAuth) BeginPasskeyRegistration(ctx context.Context, userID ULID) (*protocol.CredentialCreation, string, error) {
	return a.webauthnSvc.BeginRegistration(ctx, userID)
}

// FinishPasskeyRegistration stores the new credential. OnSignup fires with SignupMethodPasskey when
// it is the user's first credential; registration needs an authenticated user, so the first passkey
// is the closest equivalent of an account-creation moment.
func (a *TheAuth) FinishPasskeyRegistration(ctx context.Context, userID ULID, challengeToken, name string, body io.Reader) (WebAuthnCredential, error) {
	cred, isFirst, err := a.webauthnSvc.FinishRegistration(ctx, userID, challengeToken, name, body)
	if err != nil {
		return cred, err
	}
	if isFirst {
		if user, uerr := a.storage.UserByID(ctx, userID); uerr == nil {
			a.fireOnSignup(ctx, user, SignupMethodPasskey)
		}
	}
	return cred, nil
}

// BeginPasskeyLogin starts a WebAuthn assertion ceremony.
func (a *TheAuth) BeginPasskeyLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	return a.webauthnSvc.BeginLogin(ctx)
}

// FinishPasskeyLogin verifies the assertion, advances the sign counter and issues a session.
// OnSignin fires for it.
func (a *TheAuth) FinishPasskeyLogin(ctx context.Context, challengeToken string, body io.Reader, ua, ip string) (string, Session, error) {
	token, sess, err := a.webauthnSvc.FinishLogin(ctx, challengeToken, body, ua, ip)
	if err != nil {
		return token, sess, err
	}
	a.fireOnSigninForUserID(ctx, sess.UserID, &sess)
	return token, sess, nil
}

// EmitAudit enqueues an audit event for batched async write. It never blocks: when the writer
// channel is full the event is dropped and Stats.AuditDropped increments. The metadata map is
// mutated by the redactor, so callers must not reuse it. It is a no-op when Config.Audit is nil or
// after Close.
func (a *TheAuth) EmitAudit(ctx context.Context, action string, target TargetRef, metadata map[string]any) {
	a.dispatchAuthEvent(ctx, action, target, metadata)
	a.sharedSignalsTap(ctx, action, target, metadata)
	a.revocationFromAudit(ctx, action, target, metadata)
	if a.auditSvc == nil {
		return
	}
	metadata = apitokens.WithActorChain(ctx, metadata)
	var actorUser *ULID
	if u, ok := UserFromContext(ctx); ok && u != nil {
		id := u.ID
		actorUser = &id
	}
	var actorSession *Session
	if s, ok := SessionFromContext(ctx); ok && s != nil {
		actorSession = s
	}
	a.auditSvc.Emit(ctx, action, target, metadata, actorUser, actorSession)
}

// AuditChainResult is the outcome of VerifyAuditChain.
type AuditChainResult = models.AuditChainResult

// AuditChainBreak locates the first row at which an audit chain fails to verify.
type AuditChainBreak = models.AuditChainBreak

// ErrAuditUnavailable is returned by EmitDecision in fail-closed mode when a decision event cannot be queued.
var ErrAuditUnavailable = audit.ErrAuditUnavailable

// ErrAuditChainUnsupported is returned by VerifyAuditChain when the storage backend keeps no hash chain.
var ErrAuditChainUnsupported = models.ErrAuditChainUnsupported

// EmitDecision is EmitAudit for decision-class events (authorization, policy, approval,
// delegation). With Config.Audit.FailClosed set it returns ErrAuditUnavailable when the event
// cannot be queued, so the caller can deny the action. Otherwise it behaves like EmitAudit and
// returns nil.
func (a *TheAuth) EmitDecision(ctx context.Context, action string, target TargetRef, metadata map[string]any) error {
	a.dispatchAuthEvent(ctx, action, target, metadata)
	a.sharedSignalsTap(ctx, action, target, metadata)
	a.revocationFromAudit(ctx, action, target, metadata)
	if a.auditSvc == nil {
		return nil
	}
	metadata = apitokens.WithActorChain(ctx, metadata)
	var actorUser *ULID
	if u, ok := UserFromContext(ctx); ok && u != nil {
		id := u.ID
		actorUser = &id
	}
	var actorSession *Session
	if s, ok := SessionFromContext(ctx); ok && s != nil {
		actorSession = s
	}
	return a.auditSvc.EmitDecision(ctx, action, target, metadata, actorUser, actorSession)
}

// VerifyAuditChain verifies the tamper-evident hash chain. Only the sqlite backend keeps a chain;
// elsewhere it returns Supported and OK both false with ErrAuditChainUnsupported, so an unchecked
// log is never reported as verified.
func (a *TheAuth) VerifyAuditChain(ctx context.Context) (AuditChainResult, error) {
	return audit.VerifyChain(ctx, a.storage)
}

// AuditInputHash returns the hash the audit log records for input content, using
// Config.Audit.InputHashKey when set. Use it to build an AuditQuery.Provenance filter for a
// message or document you still hold:
//
//	q := theauth.AuditQuery{Provenance: &theauth.AuditProvenanceFilter{
//		Kind: audit.InputRetrievedDocument, Hash: a.AuditInputHash(doc)}}
func (a *TheAuth) AuditInputHash(content string) string { return a.auditHasher.Hash(content) }

// ShredAuditPseudonyms deletes the audit pseudonym period secrets that fell out of the retention
// window and returns the periods removed. Rotation does this by itself on the first write of each
// new period; call it to do so on demand. It needs Config.Audit.PseudonymRotation, otherwise it
// returns an error.
func (a *TheAuth) ShredAuditPseudonyms(ctx context.Context) ([]int64, error) {
	r, ok := a.storageRaw.(AuditPseudonymRotator)
	if !ok {
		return nil, errors.New("theauth: storage backend does not rotate audit pseudonyms")
	}
	return r.ShredAuditPseudonyms(ctx)
}

// QueryAudit returns up to q.Limit events and a cursor for the next page. It performs no
// authorization; callers check. q.Order is "desc" (default) or "asc" and q.Event filters by shared
// event name; both, and "c1." cursors, need a backend that declares AuditOrderSupported() true,
// otherwise it returns ErrAuditOrderUnsupported. An unknown order returns ErrBadAuditOrder and a
// cursor that does not decode for the order returns ErrBadCursor.
func (a *TheAuth) QueryAudit(ctx context.Context, q AuditQuery) ([]AuditEvent, string, error) {
	if a.auditSvc == nil {
		if err := audit.CheckQuery(a.storage, q); err != nil {
			return nil, "", err
		}
		return a.storage.QueryAuditEvents(ctx, q)
	}
	return a.auditSvc.Query(ctx, q)
}

// RevokeSession revokes one session by id. It does no ownership check; callers must authorize first.
func (a *TheAuth) RevokeSession(ctx context.Context, id ULID) error {
	if err := a.storage.RevokeSession(ctx, id); err != nil {
		return err
	}
	a.EmitAudit(ctx, "session.revoked", TargetRef{Type: "session", ID: id.String()}, nil)
	return nil
}

// RevokeUserSessions revokes every session of userID, unconditionally. To keep one session,
// re-issue or exclude it yourself.
func (a *TheAuth) RevokeUserSessions(ctx context.Context, userID ULID) error {
	if err := a.storage.RevokeUserSessions(ctx, userID); err != nil {
		return err
	}
	a.EmitAudit(ctx, "session.revoked", TargetRef{Type: "user", ID: userID.String()}, map[string]any{"scope": "all"})
	return nil
}

// SessionByID returns a session's current state (RevokedAt, ExpiresAt) by id. It lets callers
// resolve a session id from another source, such as an audit actor_session_id, without a token
// hash.
func (a *TheAuth) SessionByID(ctx context.Context, id ULID) (*Session, error) {
	return a.storage.SessionByID(ctx, id)
}

// ClientRegistrationRequest is the parsed JSON body of POST /oauth/register (RFC 7591 field names).
type ClientRegistrationRequest = internalas.ClientRegistrationRequest

// RegisterClient validates the request and mints a client_id (plus a secret for confidential
// clients). The plaintext secret is in the return value only; surface it once and never log it.
func (a *TheAuth) RegisterClient(ctx context.Context, req ClientRegistrationRequest, anonymous bool) (RegisteredClient, error) {
	if a.as == nil {
		return RegisteredClient{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.RegisterClient(ctx, req, anonymous)
}

// IntrospectionResponse is the RFC 7662 section 2.2 response, plus the act chain and
// delegation_grant_id fields.
type IntrospectionResponse = internalas.IntrospectionResponse

// IntrospectToken validates a token and returns the introspection response. JWTs are recognised by
// their three segments; anything else is looked up as a refresh token by hash. A non-empty
// expectedAud makes mismatched audiences return active=false.
func (a *TheAuth) IntrospectToken(ctx context.Context, token, clientID, clientSecret, expectedAud string) (IntrospectionResponse, []byte, error) {
	if a.as == nil {
		return IntrospectionResponse{}, nil, ErrAuthorizationServerNotConfigured
	}
	return a.as.IntrospectToken(ctx, token, clientID, clientSecret, expectedAud)
}

// RevokeToken invalidates a refresh token. Access tokens are stateless JWTs bounded by exp, and
// codes are single-use.
func (a *TheAuth) RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
	if a.as == nil {
		return ErrAuthorizationServerNotConfigured
	}
	return a.as.RevokeToken(ctx, token, tokenTypeHint, clientID, clientSecret)
}

// TokenRequest is the parsed form body of POST /oauth/token plus the authenticated client.
type TokenRequest = internalas.TokenRequest

// TokenResponse is the JSON body emitted by /oauth/token on success.
type TokenResponse = internalas.TokenResponse

// TokenExchangeRequest is the parsed form body of an RFC 8693 token-exchange call.
type TokenExchangeRequest = internalas.TokenExchangeRequest

// ExchangeAuthorizationCode redeems a one-time code for an access and refresh token pair. It
// enforces PKCE S256, redirect_uri equality, audience binding (RFC 8707) and client authentication.
func (a *TheAuth) ExchangeAuthorizationCode(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	return a.as.ExchangeAuthorizationCode(ctx, req)
}

// RefreshAccessToken rotates a refresh token. Presenting an already-rotated token revokes the whole
// family (RFC 9700 section 4.14).
func (a *TheAuth) RefreshAccessToken(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	return a.as.RefreshAccessToken(ctx, req)
}

// ClientCredentialsToken mints a self-token for an authenticated agent client (sub "agent:<id>").
// The aud is bound to the resource parameter (RFC 8707) and scope is intersected with the agent's
// registered scopes. Suspended or revoked agents fail with ErrAgentInactive (access_denied on the
// wire).
func (a *TheAuth) ClientCredentialsToken(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	return a.as.ClientCredentialsToken(ctx, req)
}

// ExchangeToken implements RFC 8693 token exchange.
func (a *TheAuth) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (TokenResponse, error) {
	return a.as.ExchangeToken(ctx, req)
}

// JWTBearerGrant implements RFC 7523 section 2.1: an external JWT from a configured
// TrustedJWTIssuer is exchanged for an AS-issued access token. It needs
// Config.AuthorizationServer.JWTBearer; otherwise ErrOAuthUnsupportedGrantType.
func (a *TheAuth) JWTBearerGrant(ctx context.Context, req TokenRequest, assertion string) (TokenResponse, error) {
	if a.as == nil {
		return TokenResponse{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.JWTBearerGrant(ctx, req, assertion)
}

// DCRRegister is RegisterClient for Go callers: the same operation as POST /oauth/register.
func (a *TheAuth) DCRRegister(ctx context.Context, req ClientRegistrationRequest) (RegisteredClient, error) {
	return a.RegisterClient(ctx, req, true)
}

// ASMetadata is the RFC 8414 document served at /.well-known/oauth-authorization-server.
type ASMetadata = internalas.ASMetadata

// ProtectedResourceMetadata is the JSON document mandated by RFC 9728.
type ProtectedResourceMetadata = internalas.ProtectedResourceMetadata

// ASMetadataDoc builds the RFC 8414 metadata document. The result is deterministic, so caching is trivial.
func (a *TheAuth) ASMetadataDoc() (ASMetadata, error) {
	if a.as == nil {
		return ASMetadata{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.ASMetadataDoc()
}

// ProtectedResourceMetadataDoc builds the RFC 9728 document for a configured resource identifier.
func (a *TheAuth) ProtectedResourceMetadataDoc(resourceID string) (ProtectedResourceMetadata, error) {
	if a.as == nil {
		return ProtectedResourceMetadata{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.ProtectedResourceMetadataDoc(resourceID)
}

// AuthorizeRequest is the parsed GET /oauth/authorize query. PKCE is required; response_type must
// be "code" and code_challenge_method must be "S256" (OAuth 2.1 forbids the implicit and password
// flows).
type AuthorizeRequest = internalas.AuthorizeRequest

// AuthorizeResult is the redirect URL to send the user agent to after a successful authorize call.
type AuthorizeResult = internalas.AuthorizeResult

// StartAuthorize validates the request. With a non-nil user it mints a code and returns the
// redirect URL; with nil the caller should redirect to LoginURL.
func (a *TheAuth) StartAuthorize(ctx context.Context, req AuthorizeRequest, user *User) (AuthorizeResult, error) {
	if a.as == nil {
		return AuthorizeResult{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.StartAuthorize(ctx, req, user)
}

// CompleteConsent resumes an authorization that ConsentHandler answered with ConsentInteract. The
// user must be the signed-in user the ticket was issued to. Protect the calling endpoint against
// CSRF. See docs/oauth-consent.md.
func (a *TheAuth) CompleteConsent(ctx context.Context, ticket string, dec ConsentDecision, user *User) (AuthorizeResult, error) {
	if a.as == nil {
		return AuthorizeResult{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.CompleteConsent(ctx, ticket, dec, user)
}

// AuthContext describes how the user authenticated (auth_time, amr). StartAuthorize callers that
// bypass the handler attach it with WithAuthContext so tokens carry auth_time, acr and amr.
type AuthContext = internalas.AuthContext

// WithAuthContext returns a context carrying ac for StartAuthorize.
func WithAuthContext(ctx context.Context, ac AuthContext) context.Context {
	return internalas.WithAuthContext(ctx, ac)
}

// IsReauthRequired reports whether a StartAuthorize error means the user must authenticate again
// (max_age or acr).
func IsReauthRequired(err error) bool { return internalas.IsReauthRequired(err) }

// IsLoginRequired reports whether an authorize error means an authenticated user is needed. Both
// packages share the sentinel, so existing errors.Is checks keep working.
func IsLoginRequired(err error) bool {
	return internalas.IsLoginRequired(err)
}

func (a *TheAuth) normalizeEmail(raw string) string { return a.emailNorm.Normalize(raw) }

func newEmailNormalizer(nfkc bool) emailnorm.Normalizer { return emailnorm.Normalizer{NFKC: nfkc} }

// NormalizeEmail returns the canonical form used for every email lookup (trimmed, lowercased, NFKC
// when Config.EmailNFKC is set).
func (a *TheAuth) NormalizeEmail(raw string) string { return a.normalizeEmail(raw) }

// ResetPasswordAdmin sets a password without a reset token, revokes sessions and clears lockouts.
// It enforces the password policy and is meant for a recover-admin command. RequirePasswordChange
// forces the user to choose their own.
func (a *TheAuth) ResetPasswordAdmin(ctx context.Context, emailAddr, newPassword string, opts ...ResetPasswordOption) error {
	var o resetPasswordOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.requireChange && (a.acct == nil || a.acct.state == nil) {
		return ErrAccountStateDisabled
	}
	userID, err := a.passwordSvc.AdminSetPassword(ctx, emailAddr, newPassword, o.requireChange)
	if err != nil {
		return err
	}
	if user, uerr := a.storage.UserByID(ctx, userID); uerr == nil {
		a.fireOnPasswordChange(ctx, user)
	}
	return nil
}

// UnlockUser clears the login and MFA lockouts for an email so the user can retry immediately.
func (a *TheAuth) UnlockUser(ctx context.Context, emailAddr string) error {
	if a.throttle == nil {
		return nil
	}
	canon := a.normalizeEmail(emailAddr)
	user, err := a.storage.UserByEmail(ctx, canon)
	userID := ""
	if err == nil && user != nil {
		userID = user.ID.String()
	}
	if err := a.throttle.UnlockIdentifier(ctx, canon, userID); err != nil {
		return fmt.Errorf("theauth: unlock user: %w", err)
	}
	return nil
}

// UserCount returns the number of user records (needs a storage implementing UserCountStorage).
func (a *TheAuth) UserCount(ctx context.Context) (int, error) {
	c, ok := a.storageRaw.(UserCountStorage)
	if !ok {
		return 0, fmt.Errorf("%w: UserCountStorage", ErrStorageMissingCapability)
	}
	n, err := c.CountUsers(ctx)
	if err != nil {
		return 0, fmt.Errorf("theauth: count users: %w", err)
	}
	return n, nil
}

// SetupToken returns the pending first-run setup token, or "" when Config.Bootstrap is unset or a
// user exists.
func (a *TheAuth) SetupToken() string {
	return a.bootstrap.Token()
}

func (a *TheAuth) handleBootstrapStatus(w http.ResponseWriter, r *http.Request) {
	n, err := a.UserCount(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		NeedsSetup bool `json:"needsSetup"`
	}{NeedsSetup: n == 0})
}

// validateAgentConfig applies defaults and screens fields in place. It stays at the root because
// AgentIdentity is a public type and its defaults must hold before any internal service sees them.
func validateAgentConfig(cfg *AgentConfig) error {
	if cfg == nil {
		return nil
	}
	if cfg.MaxChainDepth == 0 {
		cfg.MaxChainDepth = agent.ChainDepthCeiling
	}
	if cfg.MaxChainDepth < 1 {
		cfg.MaxChainDepth = 1
	}
	if cfg.MaxChainDepth > agent.ChainDepthCeiling {
		return ErrAgentChainDepthTooHigh
	}
	if cfg.MaxDelegationDuration <= 0 {
		cfg.MaxDelegationDuration = 90 * 24 * time.Hour
	}
	if cfg.DefaultDelegatedTokenTTL <= 0 {
		cfg.DefaultDelegatedTokenTTL = 15 * time.Minute
	}
	if cfg.AgentSecretLength <= 0 {
		cfg.AgentSecretLength = 32
	}
	return validateAgentRateLimit(&cfg.RateLimit)
}

// CreateAgent persists an agent owned by a user or organization with a backing OAuth client, and
// returns the agent and its one-shot secret.
func (a *TheAuth) CreateAgent(ctx context.Context, in CreateAgentInput) (Agent, AgentSecret, error) {
	return a.agentSvc.CreateAgent(ctx, in)
}

// MintAgentCredential mints a credential of the requested kind on an existing agent. Only the secret kind is
// implemented; X.509 and JWK return ErrNotImplemented.
func (a *TheAuth) MintAgentCredential(ctx context.Context, agentID ULID, kind string) (AgentSecret, error) {
	return a.agentSvc.MintAgentCredential(ctx, agentID, kind)
}

// RotateAgentSecret mints a fresh secret and revokes every prior credential. Use it on suspected
// compromise; use MintAgentCredential when overlapping credentials are wanted.
func (a *TheAuth) RotateAgentSecret(ctx context.Context, agentID ULID) (AgentSecret, error) {
	return a.agentSvc.RotateAgentSecret(ctx, agentID)
}

// ListAgentsByOwner returns every agent the supplied owner has created.
func (a *TheAuth) ListAgentsByOwner(ctx context.Context, owner AgentOwner) ([]Agent, error) {
	return a.agentSvc.ListAgentsByOwner(ctx, owner)
}

// GetAgent returns the agent record by ID.
func (a *TheAuth) GetAgent(ctx context.Context, agentID ULID) (*Agent, error) {
	return a.agentSvc.GetAgent(ctx, agentID)
}

// SuspendAgent sets status to suspended. Issued tokens mentioning the agent fail on the next
// introspection refresh.
func (a *TheAuth) SuspendAgent(ctx context.Context, agentID ULID, reason string) error {
	return a.agentSvc.SuspendAgent(ctx, agentID, reason)
}

// ResumeAgent sets a suspended agent back to active; a revoked agent cannot be resumed.
func (a *TheAuth) ResumeAgent(ctx context.Context, agentID ULID) error {
	return a.agentSvc.ResumeAgent(ctx, agentID)
}

// SetAgentExpiry sets the agent's expiry, or clears it with nil. A non-nil value must be in the
// future and no more than 10 years ahead (ErrAgentExpiryInvalid otherwise). Past the expiry the
// agent is denied with ErrAgentExpired, which matches ErrAgentInactive.
func (a *TheAuth) SetAgentExpiry(ctx context.Context, agentID ULID, expiresAt *time.Time) error {
	return a.agentSvc.SetAgentExpiry(ctx, agentID, expiresAt)
}

// RevokeAgent is terminal: a revoked agent cannot be resumed.
func (a *TheAuth) RevokeAgent(ctx context.Context, agentID ULID, reason string) error {
	return a.agentSvc.RevokeAgent(ctx, agentID, reason)
}

// startOAuth runs the /auth/providers/{name}/start flow in internal/oauth.
func (a *TheAuth) startOAuth(ctx context.Context, r *http.Request, providerName, returnTo string) (internaloauth.StartResult, error) {
	return a.oauthSvc.Start(ctx, r, providerName, returnTo)
}

// callbackOAuth runs the callback flow in internal/oauth. OnSignup fires when the user row was
// created here, and OnSignin fires for the session just issued. Hook errors never fail the request.
func (a *TheAuth) callbackOAuth(ctx context.Context, providerName, code, state, binding, userAgent, ip string) (internaloauth.CallbackResult, *User, error) {
	res, user, created, err := a.oauthSvc.Callback(ctx, providerName, code, state, binding, userAgent, ip)
	if err != nil {
		return res, user, err
	}
	sessionToken := res.SessionToken
	if created {
		a.autoProvisionPersonalOrg(ctx, user, sessionToken)
		a.fireOnSignup(ctx, user, SignupMethodOAuth)
	}
	if sess := a.sessionFromToken(ctx, sessionToken); sess != nil {
		a.fireOnSignin(ctx, user, sess)
	}
	return res, user, nil
}

// SAMLConnectionInput is the consumer-facing payload for create and update; it mirrors
// internal/saml field for field.
type SAMLConnectionInput struct {
	OrganizationID ULID
	IdPEntityID    string
	IdPSSOURL      string
	IdPX509Cert    string
	SPEntityID     string
	SPACSURL       string
	AttributeMap   SAMLAttributeMap
}

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

// DeleteSAMLConnection removes the connection and cascades its identities.
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

// FinishSAMLLogin validates an inbound SAMLResponse and runs find-or-create. OnSignup fires with
// SignupMethodSAML when the user row was created here; OnSignin fires for the session just issued.
func (a *TheAuth) FinishSAMLLogin(ctx context.Context, connectionID ULID, samlResponseB64 string, ua, ip string) (string, Session, error) {
	token, sess, isNew, err := a.samlSvc.FinishLogin(ctx, connectionID, samlResponseB64, ua, ip)
	if err != nil {
		return token, sess, err
	}
	if isNew {
		if user, uerr := a.storage.UserByID(ctx, sess.UserID); uerr == nil {
			a.fireOnSignup(ctx, user, SignupMethodSAML)
		}
	}
	a.fireOnSigninForUserID(ctx, sess.UserID, &sess)
	return token, sess, nil
}

// SAMLMetadataXML serialises the per-connection SP metadata as XML.
func (a *TheAuth) SAMLMetadataXML(ctx context.Context, connectionID ULID) ([]byte, error) {
	return a.samlSvc.MetadataXML(ctx, connectionID)
}

// ensureOrgMembership upserts a "member" role row for a user not yet in the organization. The SCIM
// handler uses it to re-enable a soft-deleted member on an idempotent POST.
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

// InvalidateProvider drops the cached ProviderResolver answer for name so an edited provider takes
// effect next request.
func (a *TheAuth) InvalidateProvider(name string) {
	if a.providerReg != nil {
		a.providerReg.Invalidate(name)
	}
}

// ListProviders returns the static providers plus those a ProviderResolver that implements
// ProviderLister reports.
func (a *TheAuth) ListProviders(ctx context.Context) ([]Provider, error) {
	if a.providerReg == nil {
		return nil, nil
	}
	return a.providerReg.List(ctx)
}

// OAuthStartResult is the provider authorization URL and the Binding secret, which goes in an
// HttpOnly cookie.
type OAuthStartResult = internaloauth.StartResult

// OAuthCallbackResult is what OAuthCallback returns on success.
type OAuthCallbackResult = internaloauth.CallbackResult

// OAuthStart begins the login flow for a named provider and returns the authorization URL. It lets
// an app host its own start route; r feeds OAuthConfig.RedirectURI. The caller must store Binding
// in a cookie.
func (a *TheAuth) OAuthStart(r *http.Request, provider, returnTo string) (OAuthStartResult, error) {
	return a.startOAuth(r.Context(), r, provider, returnTo)
}

// OAuthCallback completes the login flow for an app hosting its own callback route. It fires the
// same hooks as the built-in callback; the caller sets the session cookie from SessionToken and
// clears the binding cookie.
func (a *TheAuth) OAuthCallback(r *http.Request, provider, code, state, binding string) (OAuthCallbackResult, *User, error) {
	return a.callbackOAuth(r.Context(), provider, code, state, binding, r.UserAgent(), a.clientIPOf(r))
}

// CreateRegistrationToken mints an initial access token for POST /oauth/register. The plaintext is
// returned once; only a SHA-256 digest is stored. Needs a storage implementing
// RegistrationTokenStorage.
func (a *TheAuth) CreateRegistrationToken(ctx context.Context, in CreateRegistrationTokenInput) (RegistrationToken, string, error) {
	if a.as == nil {
		return RegistrationToken{}, "", ErrRegistrationTokensDisabled
	}
	return a.as.CreateRegistrationToken(ctx, in)
}

// ListRegistrationTokens lists tokens newest first; a nil orgID lists all. Hashes are on the model,
// so do not expose them.
func (a *TheAuth) ListRegistrationTokens(ctx context.Context, orgID *ULID) ([]RegistrationToken, error) {
	if a.as == nil {
		return nil, ErrRegistrationTokensDisabled
	}
	return a.as.ListRegistrationTokens(ctx, orgID)
}

// RevokeRegistrationToken revokes a token. Revoking twice succeeds.
func (a *TheAuth) RevokeRegistrationToken(ctx context.Context, id ULID) error {
	if a.as == nil {
		return ErrRegistrationTokensDisabled
	}
	return a.as.RevokeRegistrationToken(ctx, id, nil, nil)
}

// CreateDeviceJoinToken mints an enrollment token: a single use join token, a claim code or a bulk
// token (see CreateDeviceJoinTokenInput.Kind). The plaintext is shown once; the token fixes the
// device's name, SPIFFE ID and scopes.
func (a *TheAuth) CreateDeviceJoinToken(ctx context.Context, in CreateDeviceJoinTokenInput) (DeviceJoinToken, string, error) {
	if a.as == nil {
		return DeviceJoinToken{}, "", ErrDevicesDisabled
	}
	return a.as.CreateDeviceJoinToken(ctx, in)
}

// DeviceCertTokenRequest asks for an RFC 8705 certificate bound token for a device.
type DeviceCertTokenRequest = internalas.DeviceCertTokenRequest

// IssueDeviceCertToken mints a short lived access token for a device that the caller already
// authenticated with an X.509-SVID (iot/spiffe Bridge.IssueToken is the usual caller). The token
// carries cnf x5t#S256, so mcpresource accepts it only on a connection that presents that
// certificate. It needs Config.AuthorizationServer.DeviceTokens and issues no refresh token.
func (a *TheAuth) IssueDeviceCertToken(ctx context.Context, req DeviceCertTokenRequest) (TokenResponse, error) {
	if a.as == nil {
		return TokenResponse{}, ErrDevicesDisabled
	}
	return a.as.IssueDeviceCertToken(ctx, req)
}

// ListDevices lists registered devices, newest first.
func (a *TheAuth) ListDevices(ctx context.Context, orgID *ULID) ([]Device, error) {
	if a.as == nil {
		return nil, ErrDevicesDisabled
	}
	return a.as.ListDevices(ctx, orgID)
}

// RevokeDevice refuses the device's assertions from then on and reports its tokens inactive.
// Revoking twice succeeds.
func (a *TheAuth) RevokeDevice(ctx context.Context, id ULID) error {
	if a.as == nil {
		return ErrDevicesDisabled
	}
	return a.as.RevokeDevice(ctx, id, nil, nil)
}

// SuspendDevice puts an active device on hold: it gets no tokens until ResumeDevice. A revoked
// device returns ErrDeviceRevoked. Suspending twice succeeds.
func (a *TheAuth) SuspendDevice(ctx context.Context, id ULID) error {
	if a.as == nil {
		return ErrDevicesDisabled
	}
	return a.as.SuspendDevice(ctx, id, nil, nil)
}

// ResumeDevice lifts a suspension. A revoked device stays revoked and returns ErrDeviceRevoked.
func (a *TheAuth) ResumeDevice(ctx context.Context, id ULID) error {
	if a.as == nil {
		return ErrDevicesDisabled
	}
	return a.as.ResumeDevice(ctx, id, nil, nil)
}

// RevokeDeviceJoinToken revokes an unspent device join token.
func (a *TheAuth) RevokeDeviceJoinToken(ctx context.Context, id ULID) error {
	if a.as == nil {
		return ErrDevicesDisabled
	}
	return a.as.RevokeDeviceJoinToken(ctx, id, nil)
}

// PasskeyAuthenticatorName returns the configured display name for a credential's AAGUID, or "" when unknown.
func (a *TheAuth) PasskeyAuthenticatorName(aaguid []byte) string {
	if a.webauthnSvc == nil {
		return ""
	}
	return a.webauthnSvc.AuthenticatorName(aaguid)
}

// OIDCLogout sends back-channel logout tokens to every OpenID client that took part in sessionID,
// for logouts that skip end_session (admin revocation, account deletion). It does not revoke the
// session.
func (a *TheAuth) OIDCLogout(ctx context.Context, userID, sessionID ULID) error {
	if a.as == nil || !a.as.OIDCEnabled() {
		return ErrOIDCDisabled
	}
	a.as.NotifyLogout(ctx, userID, sessionID.String())
	return nil
}

// CreateUserInput is the input to TheAuth.CreateUser.
type CreateUserInput struct {
	// Email is required. It is validated and stored in the canonical form of NormalizeEmail.
	Email string
	// Name is an optional display name, at most 256 bytes after trimming.
	Name string
	// ID optionally fixes the user ID, for example to match your own identity provider. The zero
	// value means generate one.
	ID ULID
}

// UserError is the typed error returned by CreateUser. Compare with errors.Is against
// ErrUserInvalidInput, ErrUserEmailConflict or ErrUserIDConflict. Code uses the same names as the
// TypeScript SDK.
type UserError struct {
	// Code is "USER_INVALID_INPUT", "USER_EMAIL_CONFLICT" or "USER_ID_CONFLICT".
	Code string
	// Message is a human readable detail. It never includes the stored user's data.
	Message string
}

func (e *UserError) Error() string { return "theauth: " + e.Message }

// Is reports whether target is a *UserError with the same Code, so the Err* sentinels match any
// message.
func (e *UserError) Is(target error) bool {
	t, ok := target.(*UserError)
	return ok && t.Code == e.Code
}

var (
	// ErrUserInvalidInput means the email or another CreateUser field failed validation.
	ErrUserInvalidInput = &UserError{Code: "USER_INVALID_INPUT", Message: "invalid user input"}
	// ErrUserEmailConflict means the email is registered under a different user ID than requested.
	ErrUserEmailConflict = &UserError{Code: "USER_EMAIL_CONFLICT", Message: "email is registered under a different user id"}
	// ErrUserIDConflict means the requested user ID is already used by another email.
	ErrUserIDConflict = &UserError{Code: "USER_ID_CONFLICT", Message: "user id is already in use by another email"}
)

// createUserMu serializes the check-then-insert of CreateUser inside one process. Across processes
// the storage unique email constraint is the guard, and CreateUser re-reads on an insert error.
var createUserMu sync.Mutex

// CreateUser creates a user, or returns the existing one when the normalized email is already
// registered and in.ID is zero or equal to the stored ID. An existing user is never modified. It
// sends no email and creates no credential or session. A new user emits a "user.created" audit
// event. Errors match ErrUserInvalidInput, ErrUserEmailConflict and ErrUserIDConflict via
// errors.Is; the loser of a concurrent call with the same email gets the winner's user, not an
// error.
func (a *TheAuth) CreateUser(ctx context.Context, in CreateUserInput) (User, error) {
	emailAddr, name, err := a.validateCreateUser(in)
	if err != nil {
		return User{}, err
	}
	createUserMu.Lock()
	defer createUserMu.Unlock()

	if u, err := a.matchUser(ctx, emailAddr, in.ID); u != nil || err != nil {
		if err != nil {
			return User{}, err
		}
		return *u, nil
	}
	id := in.ID
	if id == (ULID{}) {
		id = ulid.New()
	}
	now := time.Now()
	created, err := a.storage.CreateUser(ctx, User{ID: id, Email: emailAddr, Name: name, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		// Another process may have inserted the same email first: apply the same rules to its row.
		if u, merr := a.matchUser(ctx, emailAddr, in.ID); merr != nil {
			return User{}, merr
		} else if u != nil {
			return *u, nil
		}
		return User{}, err
	}
	a.EmitAudit(ctx, "user.created", TargetRef{Type: "user", ID: created.ID.String()}, map[string]any{
		"email_ref": emailnorm.LogRef(emailAddr),
	})
	return created, nil
}

// validateCreateUser returns the normalized email and trimmed name, or an ErrUserInvalidInput match.
func (a *TheAuth) validateCreateUser(in CreateUserInput) (emailAddr, name string, err error) {
	raw := a.normalizeEmail(in.Email)
	if raw == "" || len(raw) > 320 {
		return "", "", &UserError{Code: ErrUserInvalidInput.Code, Message: "invalid user input: email must be 1 to 320 characters"}
	}
	addr, perr := mail.ParseAddress(raw)
	if perr != nil || addr.Address != raw {
		return "", "", &UserError{Code: ErrUserInvalidInput.Code, Message: "invalid user input: email is not a valid address"}
	}
	name = strings.TrimSpace(in.Name)
	if len(name) > 256 {
		return "", "", &UserError{Code: ErrUserInvalidInput.Code, Message: "invalid user input: name is longer than 256 bytes"}
	}
	return raw, name, nil
}

// matchUser applies the idempotency rules. It returns the user to reuse, nil when nothing matches,
// or a conflict error.
func (a *TheAuth) matchUser(ctx context.Context, emailAddr string, id ULID) (*User, error) {
	byEmail, err := a.storage.UserByEmail(ctx, emailAddr)
	switch {
	case err == nil && byEmail != nil:
		if id == (ULID{}) || byEmail.ID == id {
			return byEmail, nil
		}
		return nil, &UserError{Code: ErrUserEmailConflict.Code, Message: "email is registered under a different user id than " + id.String()}
	case err != nil && !errors.Is(err, ErrStorageNotFound):
		return nil, err
	}
	if id == (ULID{}) {
		return nil, nil
	}
	byID, err := a.storage.UserByID(ctx, id)
	switch {
	case err == nil && byID != nil:
		return nil, &UserError{Code: ErrUserIDConflict.Code, Message: "user id " + id.String() + " is already in use by another email"}
	case err != nil && !errors.Is(err, ErrStorageNotFound):
		return nil, err
	}
	return nil, nil
}
