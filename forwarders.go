package theauth

// forwarders.go consolidates every thin *TheAuth method shim that
// delegates to an internal/<flow> Service into a single file. PR I
// (2026-06-22) merged the prior forwarders_identity.go (v0.1 to v0.5
// identity flows: session, magic-link, password, TOTP, WebAuthn,
// audit) and forwarders_oauth.go (v2.0 OAuth 2.1 authorization server
// surface: DCR, introspect, revoke, token grants, metadata, authorize)
// into this file so the repository root has fewer files and the README
// renders above the fold on GitHub. Every method below is a one-line
// thunk over the matching internal/<flow>.Service; substantive logic
// lives in those packages. Public API surface and signatures are
// byte-stable.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	internalas "github.com/glincker/theauth-go/internal/as"
	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/password"
	"github.com/glincker/theauth-go/internal/totp"
	"github.com/go-webauthn/webauthn/protocol"
)

// ---------- v2.5 Lifecycle hook plumbing ----------

// coalesceLifecycleHooks returns the consumer-supplied LifecycleHooks or
// the zero-value pointer when nil so dispatch sites can call the fireOn*
// helpers without nil-checking the bundle. Individual fields inside the
// bundle MAY still be nil; the fireOn* helpers handle that.
func coalesceLifecycleHooks(h *LifecycleHooks) *LifecycleHooks {
	if h == nil {
		return &LifecycleHooks{}
	}
	return h
}

// runLifecycleHook is the panic-and-error-safe runner shared by every
// fireOn* helper. Errors are logged at Warn level; panics are recovered
// and logged at Error level. The triggering operation is never failed by
// a hook (semantic: hooks are fire-and-observe; for request-failing side
// effects, wrap at the HTTP boundary).
func runLifecycleHook(ctx context.Context, name string, fn func() error) {
	if fn == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			slog.ErrorContext(ctx, "theauth: lifecycle hook panicked", "hook", name, "panic", r)
		}
	}()
	if err := fn(); err != nil {
		slog.WarnContext(ctx, "theauth: lifecycle hook returned error", "hook", name, "err", err.Error())
	}
}

// fireOnSignup dispatches LifecycleHooks.OnSignup. Silent no-op when the
// hook is unset.
func (a *TheAuth) fireOnSignup(ctx context.Context, user *User, method SignupMethod) {
	if a.lifecycle.OnSignup == nil || user == nil {
		return
	}
	runLifecycleHook(ctx, "OnSignup", func() error {
		return a.lifecycle.OnSignup(ctx, user, method)
	})
}

// fireOnSignin dispatches LifecycleHooks.OnSignin. Silent no-op when the
// hook is unset.
func (a *TheAuth) fireOnSignin(ctx context.Context, user *User, sess *Session) {
	if a.lifecycle.OnSignin == nil || user == nil || sess == nil {
		return
	}
	runLifecycleHook(ctx, "OnSignin", func() error {
		return a.lifecycle.OnSignin(ctx, user, sess)
	})
}

// ---------- v2.5 Public lookup helpers ----------

// UserByID looks up a user by ID. Returns (nil, ErrNotFound) when the row
// does not exist. Added in v2.5 to unblock consumer code that previously
// had no public accessor and had to reach into storage directly (consumer
// feedback 2026-06-22).
func (a *TheAuth) UserByID(ctx context.Context, id ULID) (*User, error) {
	return a.storage.UserByID(ctx, id)
}

// ErrAuthorizationServerNotConfigured is returned by authorization-server
// methods when Config.AuthorizationServer was not set at New time.
// Callers can use errors.Is(err, theauth.ErrAuthorizationServerNotConfigured)
// to distinguish this condition from other errors.
var ErrAuthorizationServerNotConfigured = errors.New("theauth: authorization server not configured")

// ---------- Identity flows (v0.1 to v0.5: session, magic-link, password, TOTP, WebAuthn, audit) ----------

// PR G (2026-06-21) merged the previous service_session.go,
// service_magiclink.go, service_password.go, service_totp.go,
// service_webauthn.go, and service_audit.go files here so the root
// package presents one place to look for the bridge between the public
// *TheAuth surface and the extracted flow services. No behaviour change;
// signatures are byte-stable with the v2.0 release.

// ---------- Password (v0.2) re-exports ----------

// MinPasswordLength is enforced at the library level (NIST 2024 baseline).
const MinPasswordLength = password.MinPasswordLength

// PasswordResetTTL is how long a reset token stays valid after issuance.
const PasswordResetTTL = password.PasswordResetTTL

// SigninStep mirrors the v0.5 step indicator returned by signinWithPassword.
type SigninStep = password.SigninStep

// SigninStep values re-exported for the v0.5 public surface.
const (
	SigninStepFull         = password.SigninStepFull
	SigninStepTOTPRequired = password.SigninStepTOTPRequired
)

// ---------- TOTP (v0.5) re-exports ----------

// EnrollTOTPResult is returned by BeginTOTPEnrollment for the caller to
// render. Re-exported as an alias so the v0.5 public surface is
// unchanged.
type EnrollTOTPResult = totp.EnrollResult

// ---------- Audit (v1.0) re-exports ----------

// AuditMetadata is the optional bundle a caller may attach to a context to
// override the auto-derived actor / org / IP / UA. Re-exported from
// internal/audit so the v1.0 public surface is unchanged.
type AuditMetadata = audit.AuditMetadata

// WithAuditMetadata attaches an AuditMetadata to ctx; EmitAudit reads it.
func WithAuditMetadata(ctx context.Context, md AuditMetadata) context.Context {
	return audit.WithAuditMetadata(ctx, md)
}

// ---------- Session forwarders ----------

// issueSession mints a fresh opaque token, stores its sha256 hash with a
// new Session row, and returns the raw token. The raw token is what the
// caller puts in a cookie / sends to the user; the hash is what's
// persisted. Forwards to sessionSvc.Issue.
func (a *TheAuth) issueSession(ctx context.Context, user User, userAgent, ip string) (token string, sess Session, err error) {
	return a.sessionSvc.Issue(ctx, user, userAgent, ip)
}

// validateSession looks up a session by the hash of the supplied token,
// verifies it is not expired or revoked, and returns the session and its
// user. Returns ErrInvalidToken for missing/unknown tokens and
// ErrSessionExpired for expired or revoked sessions. Forwards to
// sessionSvc.Validate.
func (a *TheAuth) validateSession(ctx context.Context, token string) (*Session, *User, error) {
	return a.sessionSvc.Validate(ctx, token)
}

// IssueSessionByUserID mints a full session for the given user without
// requiring an existing session token. Used by the account-linking flow after
// OTP verification to sign the user in to their existing account.
func (a *TheAuth) IssueSessionByUserID(ctx context.Context, userID ULID, userAgent, ip string) (string, error) {
	u, err := a.UserByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("theauth: user not found for session: %w", err)
	}
	tok, _, err := a.issueSession(ctx, *u, userAgent, ip)
	return tok, err
}

// LinkOAuthProviderBySession links an OAuth provider account to the user
// identified by sessionToken. Intended for the post-OTP account-linking flow
// where the session was just issued by IssueSessionByUserID.
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

// ---------- Magic-link forwarders ----------

// requestMagicLink mints a magic-link token, persists its hash, and emails
// the raw token to the user as a click-through verification link.
// Production code calls this; the raw token only ever appears in the
// inbox. Forwards to magicSvc.Request.
func (a *TheAuth) requestMagicLink(ctx context.Context, emailAddr string) error {
	return a.magicSvc.Request(ctx, emailAddr)
}

// requestMagicLinkForTest is the test seam: same behaviour as
// requestMagicLink but additionally returns the raw token so tests can
// assert. Production code never calls this. Forwards to
// magicSvc.RequestForTest.
func (a *TheAuth) requestMagicLinkForTest(ctx context.Context, emailAddr string) (string, error) {
	return a.magicSvc.RequestForTest(ctx, emailAddr)
}

// consumeMagicLink validates the supplied token (single-use,
// time-bounded), finds-or-creates the user, marks the email verified, and
// issues a session. Forwards to magicSvc.Consume. Dispatches OnSignup
// when the user row was created during this call, then OnSignin for the
// session that was just issued. Hook errors and panics are logged but do
// NOT fail the request.
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

// ---------- Password forwarders ----------

// validateEmail forwards to password.ValidateEmail for the fuzz seam.
// Used by the export_test.go ValidateEmailForTest shim.
func validateEmail(raw string) (string, error) {
	return password.ValidateEmail(raw)
}

// signupWithPassword creates a new user with email + password credentials
// and issues a session. Forwards to passwordSvc.Signup, then dispatches
// the LifecycleHooks.OnSignup hook (no-op when unset). Hook errors and
// panics are logged but do NOT fail the request; the user has already been
// created.
func (a *TheAuth) signupWithPassword(ctx context.Context, emailAddr, pw string) (*User, string, error) {
	user, token, err := a.passwordSvc.Signup(ctx, emailAddr, pw)
	if err != nil {
		return user, token, err
	}
	a.autoProvisionPersonalOrg(ctx, user, token)
	a.fireOnSignup(ctx, user, SignupMethodPassword)
	return user, token, nil
}

// signinWithPassword verifies credentials and issues a session. Forwards
// to passwordSvc.Signin, then dispatches the LifecycleHooks.OnSignin hook
// when the returned SigninStep indicates a full sign-in (not a step-up
// intermediate). pending_2fa intermediates do NOT fire OnSignin; the hook
// fires on the subsequent TOTP/WebAuthn verify that completes the session.
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

// sessionFromToken resolves a freshly-issued session token to its Session
// row for hook dispatch. Returns nil on lookup failure rather than failing
// the surrounding flow; missing a hook fire is preferable to failing a
// signin that already succeeded.
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

// requestPasswordResetForTest is the testable variant; returns the raw
// token when one is minted, "" when the email does not exist. Forwards
// to passwordSvc.RequestResetForTest.
func (a *TheAuth) requestPasswordResetForTest(ctx context.Context, emailAddr string) (string, error) {
	return a.passwordSvc.RequestResetForTest(ctx, emailAddr)
}

// resetPassword atomically consumes a reset token, updates the user's
// password, and revokes all existing sessions. Forwards to
// passwordSvc.Reset.
func (a *TheAuth) resetPassword(ctx context.Context, token, newPassword string) error {
	return a.passwordSvc.Reset(ctx, token, newPassword)
}

// ---------- TOTP forwarders ----------

// BeginTOTPEnrollment generates a fresh shared secret and otpauth URL,
// returns them to the caller (the secret is displayed exactly once), and
// stashes the plaintext in the in-memory pending map. Forwards to
// totpSvc.BeginEnrollment.
func (a *TheAuth) BeginTOTPEnrollment(ctx context.Context, userID ULID, accountName string) (EnrollTOTPResult, error) {
	return a.totpSvc.BeginEnrollment(ctx, userID, accountName)
}

// FinishTOTPEnrollment validates one code against the pending secret,
// confirms the row, generates recovery codes, and returns them to the
// caller. Forwards to totpSvc.FinishEnrollment.
func (a *TheAuth) FinishTOTPEnrollment(ctx context.Context, userID ULID, enrollmentID, code string) ([]string, error) {
	return a.totpSvc.FinishEnrollment(ctx, userID, enrollmentID, code)
}

// IssuePending2FA mints a short-lived session whose AuthLevel is
// AuthLevelPending2FA. Forwards to totpSvc.IssuePending2FA.
func (a *TheAuth) IssuePending2FA(ctx context.Context, userID ULID, ua, ip string) (string, Session, error) {
	return a.totpSvc.IssuePending2FA(ctx, userID, ua, ip)
}

// VerifyTOTP consumes a 6-digit code against the user's confirmed secret,
// upgrades their pending session to full, and returns the (same) token
// with the upgraded session row. Forwards to totpSvc.Verify.
func (a *TheAuth) VerifyTOTP(ctx context.Context, pendingSessionToken, code string) (string, Session, error) {
	return a.totpSvc.Verify(ctx, pendingSessionToken, code)
}

// ConsumeRecoveryCode upgrades a pending session by consuming one unused
// recovery code. Forwards to totpSvc.ConsumeRecoveryCode.
func (a *TheAuth) ConsumeRecoveryCode(ctx context.Context, pendingSessionToken, code string) (string, Session, error) {
	return a.totpSvc.ConsumeRecoveryCode(ctx, pendingSessionToken, code)
}

// ---------- WebAuthn forwarders ----------

// BeginPasskeyRegistration starts a WebAuthn credential creation
// ceremony: returns a serialised PublicKeyCredentialCreationOptions plus
// an opaque challenge token the caller stores in a short-lived cookie.
// Forwards to webauthnSvc.BeginRegistration.
func (a *TheAuth) BeginPasskeyRegistration(ctx context.Context, userID ULID) (*protocol.CredentialCreation, string, error) {
	return a.webauthnSvc.BeginRegistration(ctx, userID)
}

// FinishPasskeyRegistration validates the navigator.credentials.create
// response, stores the resulting credential, and returns the stored row.
// Forwards to webauthnSvc.FinishRegistration.
func (a *TheAuth) FinishPasskeyRegistration(ctx context.Context, userID ULID, challengeToken, name string, body io.Reader) (WebAuthnCredential, error) {
	return a.webauthnSvc.FinishRegistration(ctx, userID, challengeToken, name, body)
}

// BeginPasskeyLogin starts a WebAuthn assertion ceremony. Returns a
// serialised PublicKeyCredentialRequestOptions and an opaque challenge
// token. Forwards to webauthnSvc.BeginLogin.
func (a *TheAuth) BeginPasskeyLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	return a.webauthnSvc.BeginLogin(ctx)
}

// FinishPasskeyLogin validates the navigator.credentials.get response,
// looks up the credential by ID, advances the stored sign counter, and
// issues a session. Forwards to webauthnSvc.FinishLogin.
func (a *TheAuth) FinishPasskeyLogin(ctx context.Context, challengeToken string, body io.Reader, ua, ip string) (string, Session, error) {
	return a.webauthnSvc.FinishLogin(ctx, challengeToken, body, ua, ip)
}

// Note: the previous unexported helpers finishRegistrationFromRequest /
// finishLoginFromRequest wrapped the body in http.MaxBytesReader before
// delegating to FinishPasskey{Registration,Login}. PR G (2026-06-21)
// removed them because every in-tree handler now performs the
// MaxBytesReader wrap itself (see internal/webauthn/handlers).

// ---------- Audit forwarders ----------

// EmitAudit enqueues an audit event for asynchronous batched write. Non-
// blocking: when the writer channel is full the event is dropped and
// Stats.AuditDropped increments by 1.
//
// EmitAudit may be called from any goroutine. The metadata map is mutated
// in place by the redactor; callers must not retain references after the
// call (or, equivalently, must defensively copy before passing in).
//
// When Config.Audit is nil EmitAudit is a silent no-op. When Close has
// been called EmitAudit is also a silent no-op. Forwards to
// auditSvc.Emit.
func (a *TheAuth) EmitAudit(ctx context.Context, action string, target TargetRef, metadata map[string]any) {
	if a.auditSvc == nil {
		return
	}
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

// QueryAudit returns up to q.Limit events plus an opaque cursor for the
// next page. Caller is responsible for permission-checking; this method
// does no auth. Forwards to auditSvc.Query (or to storage.QueryAuditEvents
// when Config.Audit is nil).
func (a *TheAuth) QueryAudit(ctx context.Context, q AuditQuery) ([]AuditEvent, string, error) {
	if a.auditSvc == nil {
		return a.storage.QueryAuditEvents(ctx, q)
	}
	return a.auditSvc.Query(ctx, q)
}

// ---------- OAuth 2.1 authorization server (v2.0: DCR, introspect, revoke, token, metadata, authorize) ----------
// ---------- DCR (RFC 7591) ----------

// ClientRegistrationRequest is the parsed JSON body of POST
// /oauth/register. Field names match RFC 7591 client metadata exactly so
// the wire form maps 1:1 onto the struct.
type ClientRegistrationRequest = internalas.ClientRegistrationRequest

// RegisterClient validates the request, mints a client_id (and a secret
// for confidential clients), persists the OAuthClient row, and returns
// the RFC 7591 response body. The plaintext secret is in the return
// value; callers must surface it to the caller exactly once and never
// log it. Forwards to as.RegisterClient.
func (a *TheAuth) RegisterClient(ctx context.Context, req ClientRegistrationRequest, anonymous bool) (RegisteredClient, error) {
	if a.as == nil {
		return RegisteredClient{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.RegisterClient(ctx, req, anonymous)
}

// ---------- Introspection (RFC 7662) ----------

// IntrospectionResponse mirrors the JSON shape mandated by RFC 7662
// section 2.2 plus the v2.0 act chain and delegation_grant_id
// forward-compatibility fields.
type IntrospectionResponse = internalas.IntrospectionResponse

// IntrospectToken validates the supplied token and returns the
// structured introspection response. Token type detection: JWTs are
// recognised by the three dot-separated base64 segments; everything else
// is treated as a refresh token (looked up by hash).
//
// Audience binding: when expectedAud is non-empty (resource server
// passes its own identifier), tokens with a mismatching aud return
// active=false. Forwards to as.IntrospectToken.
func (a *TheAuth) IntrospectToken(ctx context.Context, token, clientID, clientSecret, expectedAud string) (IntrospectionResponse, []byte, error) {
	if a.as == nil {
		return IntrospectionResponse{}, nil, ErrAuthorizationServerNotConfigured
	}
	return a.as.IntrospectToken(ctx, token, clientID, clientSecret, expectedAud)
}

// ---------- Revocation (RFC 7009) ----------

// RevokeToken invalidates a refresh token. Authorization codes and
// access tokens are out of scope for this entry: codes are single-use
// anyway, and access tokens are stateless JWTs whose lifetime is
// bounded by exp. Forwards to as.RevokeToken.
func (a *TheAuth) RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
	if a.as == nil {
		return ErrAuthorizationServerNotConfigured
	}
	return a.as.RevokeToken(ctx, token, tokenTypeHint, clientID, clientSecret)
}

// ---------- Token grants ----------

// TokenRequest is the parsed form-encoded body of a POST /oauth/token
// call, plus the authenticated client extracted from the request line /
// headers.
type TokenRequest = internalas.TokenRequest

// TokenResponse is the JSON body emitted by /oauth/token on success.
type TokenResponse = internalas.TokenResponse

// TokenExchangeRequest is the parsed form-encoded body of a
// token-exchange call. Field names map 1:1 onto the RFC 8693 wire form.
type TokenExchangeRequest = internalas.TokenExchangeRequest

// ExchangeAuthorizationCode redeems a one-time authorization code for
// an access token + refresh token pair. Enforces PKCE S256,
// redirect_uri equality, audience binding (RFC 8707), and client
// authentication. Forwards to as.ExchangeAuthorizationCode.
func (a *TheAuth) ExchangeAuthorizationCode(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	return a.as.ExchangeAuthorizationCode(ctx, req)
}

// RefreshAccessToken rotates a refresh token, returning a new access
// token + refresh token pair. The old refresh token is revoked;
// presenting it again triggers family-wide revocation per RFC 9700
// section 4.14. Forwards to as.RefreshAccessToken.
func (a *TheAuth) RefreshAccessToken(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	return a.as.RefreshAccessToken(ctx, req)
}

// ClientCredentialsToken mints a self-token for the authenticated agent
// client. The token's sub is "agent:<id>"; aud is bound to the resource
// parameter (RFC 8707); scope is intersected with both the agent's
// registered scope set and the resource catalog. Suspended / revoked
// agents fail with ErrAgentInactive (mapped to access_denied at the
// wire).
//
// Audit emission: agent.token_minted on success. Forwards to
// as.ClientCredentialsToken.
func (a *TheAuth) ClientCredentialsToken(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	return a.as.ClientCredentialsToken(ctx, req)
}

// ExchangeToken implements RFC 8693 token exchange. Forwards to
// as.ExchangeToken.
func (a *TheAuth) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (TokenResponse, error) {
	return a.as.ExchangeToken(ctx, req)
}

// JWTBearerGrant implements RFC 7523 section 2.1: an externally-issued JWT
// is exchanged for an AS-issued access token. The assertion parameter must
// be the compact serialized JWT from a configured TrustedJWTIssuer.
//
// Requires Config.AuthorizationServer.JWTBearer to be non-nil; returns
// ErrOAuthUnsupportedGrantType when not configured.
func (a *TheAuth) JWTBearerGrant(ctx context.Context, req TokenRequest, assertion string) (TokenResponse, error) {
	if a.as == nil {
		return TokenResponse{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.JWTBearerGrant(ctx, req, assertion)
}

// DCRRegister is a convenience wrapper around RegisterClient that registers
// a new OAuth client with AllowAnonymousRegistration semantics. The returned
// RegisteredClient carries ClientID and ClientSecret. This is the same
// operation as POST /oauth/register but callable from Go code directly.
func (a *TheAuth) DCRRegister(ctx context.Context, req ClientRegistrationRequest) (RegisteredClient, error) {
	return a.RegisterClient(ctx, req, true)
}

// Note: the previous unexported helper authenticateClient was removed in
// PR G (2026-06-21). Every in-tree caller now invokes
// a.as.AuthenticateClient directly (the introspect / revoke / token
// endpoints all live in internal/as/handlers).

// ---------- Metadata (RFC 8414, RFC 9728) ----------

// ASMetadata is the JSON document served at
// /.well-known/oauth-authorization-server. Field names and shape follow
// RFC 8414 section 2.
type ASMetadata = internalas.ASMetadata

// ProtectedResourceMetadata is the JSON document mandated by RFC 9728.
type ProtectedResourceMetadata = internalas.ProtectedResourceMetadata

// ASMetadataDoc builds the RFC 8414 metadata document. The result is
// deterministic across calls so handler caching is trivial. Forwards to
// as.ASMetadataDoc.
func (a *TheAuth) ASMetadataDoc() (ASMetadata, error) {
	if a.as == nil {
		return ASMetadata{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.ASMetadataDoc()
}

// ProtectedResourceMetadataDoc builds the RFC 9728 document for the
// resource matching the supplied identifier. Returns an error when the
// identifier is not one of the configured resources. Forwards to
// as.ProtectedResourceMetadataDoc.
func (a *TheAuth) ProtectedResourceMetadataDoc(resourceID string) (ProtectedResourceMetadata, error) {
	if a.as == nil {
		return ProtectedResourceMetadata{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.ProtectedResourceMetadataDoc(resourceID)
}

// ---------- Authorize ----------

// AuthorizeRequest is the parsed GET /oauth/authorize query string.
// PKCE fields are required; OAuth 2.1 forbids the legacy implicit and
// password flows so response_type MUST be "code" and
// code_challenge_method MUST be "S256".
type AuthorizeRequest = internalas.AuthorizeRequest

// AuthorizeResult is the outcome of a successful authorize call: the
// redirect URL the handler should 302 the user agent to.
type AuthorizeResult = internalas.AuthorizeResult

// StartAuthorize validates the request and, when the supplied user is
// non-nil, immediately mints an authorization code bound to the request
// and returns a redirect URL with code + state. When user is nil the
// caller should redirect to LoginURL so the user can sign in. Forwards
// to as.StartAuthorize.
func (a *TheAuth) StartAuthorize(ctx context.Context, req AuthorizeRequest, user *User) (AuthorizeResult, error) {
	if a.as == nil {
		return AuthorizeResult{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.StartAuthorize(ctx, req, user)
}

// IsLoginRequired reports whether the supplied error signals the
// authorize path needs an authenticated user. Forwards to
// internalas.IsLoginRequired; both packages share the same sentinel
// pointer so existing errors.Is callers keep working.
func IsLoginRequired(err error) bool {
	return internalas.IsLoginRequired(err)
}
