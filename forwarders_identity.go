package theauth

import (
	"context"
	"io"

	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/password"
	"github.com/glincker/theauth-go/internal/totp"
	"github.com/go-webauthn/webauthn/protocol"
)

// forwarders_identity.go consolidates the v0.1 - v0.5 identity-flow
// forwarders (session, magic-link, password, TOTP, WebAuthn, audit) into a
// single file. Each method below is a one-line thunk that calls into the
// matching internal/<flow> Service; the substantive logic lives in those
// packages. PR G (2026-06-21) merged the previous service_session.go,
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
// issues a session. Forwards to magicSvc.Consume.
func (a *TheAuth) consumeMagicLink(ctx context.Context, token string) (sessionToken string, user *User, err error) {
	return a.magicSvc.Consume(ctx, token)
}

// ---------- Password forwarders ----------

// validateEmail forwards to password.ValidateEmail for the fuzz seam.
// Used by the export_test.go ValidateEmailForTest shim.
func validateEmail(raw string) (string, error) {
	return password.ValidateEmail(raw)
}

// signupWithPassword creates a new user with email + password credentials
// and issues a session. Forwards to passwordSvc.Signup.
func (a *TheAuth) signupWithPassword(ctx context.Context, emailAddr, pw string) (*User, string, error) {
	return a.passwordSvc.Signup(ctx, emailAddr, pw)
}

// signinWithPassword verifies credentials and issues a session. Forwards
// to passwordSvc.Signin.
func (a *TheAuth) signinWithPassword(ctx context.Context, emailAddr, pw, userAgent, ip string) (string, *User, SigninStep, error) {
	return a.passwordSvc.Signin(ctx, emailAddr, pw, userAgent, ip)
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
