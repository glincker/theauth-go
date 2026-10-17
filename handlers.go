package theauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/mail"
	"strconv"
	"time"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
	ashandlers "github.com/glincker/theauth-go/v2/internal/as/handlers"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/models"
	internaloauth "github.com/glincker/theauth-go/v2/internal/oauth"
	oauthhandlers "github.com/glincker/theauth-go/v2/internal/oauth/handlers"
	passwordhandlers "github.com/glincker/theauth-go/v2/internal/password/handlers"
	totphandlers "github.com/glincker/theauth-go/v2/internal/totp/handlers"
	webauthnhandlers "github.com/glincker/theauth-go/v2/internal/webauthn/handlers"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
)

// Mount wires TheAuth's HTTP routes onto the supplied chi router under /auth.
//
// POST /auth/magic-link - request a magic link
// GET /auth/magic-link/verify - consume a magic link, set session cookie
// POST /auth/email-password/signup - create user with email + password (rate-limited)
// POST /auth/email-password/signin - sign in with email + password (rate-limited)
// POST /auth/email-password/forgot - request a password reset link (rate-limited)
// POST /auth/email-password/reset - consume a reset token + set new password (rate-limited)
// GET /auth/me - return the authenticated user (RequireAuth)
// DELETE /auth/sessions/current - revoke the current session (RequireAuth)
// GET /auth/sessions - list the caller's sessions (SessionManagementStorage)
// DELETE /auth/sessions/{id} - revoke one of the caller's sessions
// POST /auth/sessions/revoke-others - revoke every session but the current one
// POST /auth/step-up - elevate the session (password, totp or passkey)
// POST /auth/password/change - change password, rotate the session
// POST /auth/session-link/consume - exchange a session link (Config.SessionLinks)
//
// Default rate limits: 5/min per source IP on every credential endpoint, plus 3/min per email on signin + forgot. All limits are in-memory unless Config.Stores.RateLimiter supplies a shared one.
func (a *TheAuth) Mount(r chi.Router) {
	r.Group(func(r chi.Router) {
		if a.admission != nil {
			r.Use(a.Admission(*a.admission))
		}
		r.Use(a.securityMiddleware, a.auditContextMiddleware)
		a.mountRoutes(r)
		a.mountAccountDelete(r)
	})
}

func (a *TheAuth) mountRoutes(r chi.Router) {
	// Limiters are built once so every route mounted here shares the same buckets.
	ipLimit := a.RateLimitByIP(a.rateLimitPerIP)
	emailLimit := a.RateLimitByEmail(a.rateLimitPerEmail)

	r.Route(a.pathPrefix, func(r chi.Router) {
		// magic-link requests are rate limited too, so registered addresses cannot be enumerated
		// (security re-audit L1).
		r.With(ipLimit, emailLimit).Post("/magic-link", a.handleMagicLinkRequest)
		if a.bootstrap != nil {
			r.Get("/bootstrap/status", a.handleBootstrapStatus)
		}
		r.Get("/magic-link/verify", a.handleMagicLinkVerify)

		r.Route("/email-password", func(r chi.Router) {
			a.mountPasswordHandlers(r, ipLimit, emailLimit)
		})

		// OAuth routes mount only when at least one provider is registered.
		if a.oauthSvc != nil {
			a.mountOAuth(r, ipLimit)
		}

		if a.webauthnCfg != nil {
			a.mountWebAuthn(r, ipLimit)
		}

		if a.totpCfg != nil {
			a.mountTOTP(r, ipLimit)
		}

		// Organization routes mount only when Config.Organizations is set. SAML and SCIM token subroutes
		// hang off the org tree.
		if a.orgsCfg != nil {
			a.mountOrganizations(r)
		}
		// SAML flow endpoints mount only when Config.SAML is set. Connection CRUD lives under
		// /auth/orgs/{orgId}/saml/connections.
		if a.samlCfg != nil {
			a.mountSAML(r)
		}

		if a.apiTokens != nil {
			a.apiTokens.MountTokens(r, ipLimit)
			a.mountDoctor(r, ipLimit)
			if a.apiTokens.DeviceEnabled() {
				a.apiTokens.MountDevice(r, ipLimit)
			}
		}

		a.mountSessionManagement(r, ipLimit)
		r.With(a.RequireAuth()).Delete("/sessions/current", a.handleSessionDelete)
		r.With(a.RequireAuth()).Get("/me", a.handleMe)
	})

	// SCIM 2.0 endpoints mount at /scim/v2/ so the standard prefix is kept.
	if a.scimCfg != nil {
		a.mountSCIM(r)
	}

	// Admin API mounts at /admin/v1/* (or AdminConfig.PathPrefix) when Config.Admin is set; it requires RBAC.
	if a.adminCfg != nil {
		a.mountAdmin(r)
	}

	// OAuth 2.1 authorization server routes mount at /.well-known/* and /oauth/* when
	// Config.AuthorizationServer is set.
	if a.as != nil {
		a.mountAS(r)
	}

	// End-user /account routes are session-gated and mount only when AccountUX is set.
	if a.accountUX {
		a.mountAccount(r)
	}
}

func (a *TheAuth) handleMagicLinkRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14) // 16 KiB cap to prevent memory DoS
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		httpx.Error(w, http.StatusBadRequest, "invalid body")
		return
	}
	addr, err := mail.ParseAddress(a.normalizeEmail(body.Email))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid email")
		return
	}
	email := a.normalizeEmail(addr.Address)
	if err := a.requestMagicLink(r.Context(), email); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"sent":true}`))
}

func (a *TheAuth) handleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		httpx.Error(w, http.StatusBadRequest, "missing token")
		return
	}
	sessToken, _, err := a.consumeMagicLink(r.Context(), token)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    sessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(a.sessionTTL),
	})
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (a *TheAuth) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(user)
}

func (a *TheAuth) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	sess, ok := SessionFromContext(r.Context())
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := a.storage.RevokeSession(r.Context(), sess.ID); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "internal error")
		return
	}
	a.EmitAudit(r.Context(), "user.logout", TargetRef{Type: "session", ID: sess.ID.String()}, nil)
	slog.Info("theauth: session revoked", "user_id", sess.UserID.String(), "session_id", sess.ID.String())
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func errToHTTP(w http.ResponseWriter, err error) {
	// Prefer the TheAuthError code mapping, which gives callers a stable Code in the response body.
	var te *TheAuthError
	if errors.As(err, &te) {
		switch te.Code {
		case CodeWeakPassword:
			writeJSONError(w, http.StatusBadRequest, te.Code, te.Message)
		case CodeEmailTaken:
			writeJSONError(w, http.StatusConflict, te.Code, te.Message)
		case CodeInvalidCredentials:
			writeJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		case CodeRateLimited, CodeAccountLocked:
			if te.RetryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(te.RetryAfter.Seconds()))))
			}
			writeJSONError(w, http.StatusTooManyRequests, te.Code, te.Message)
		case CodeSignupClosed, CodeSetupTokenInvalid:
			writeJSONError(w, http.StatusForbidden, te.Code, te.Message)
		case CodePasswordResetExpired, CodePasswordResetInvalid:
			writeJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		case CodeInvalidTOTP, CodeWebAuthn:
			// 401 because the supplied factor is invalid; a malformed request was already rejected above.
			writeJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		case CodeAlreadyEnrolled:
			writeJSONError(w, http.StatusConflict, te.Code, te.Message)
		case CodePasswordChangeRequired, CodeAccountDisabled, CodeReauthRequired:
			writeJSONError(w, http.StatusForbidden, te.Code, te.Message)
		case CodeSessionLimit:
			writeJSONError(w, http.StatusConflict, te.Code, te.Message)
		case CodeTOTPRequired:
			writeJSONError(w, http.StatusOK, te.Code, te.Message)
		default:
			writeJSONError(w, http.StatusInternalServerError, te.Code, "internal error")
		}
		return
	}
	switch {
	case errors.Is(err, ErrInvalidToken),
		errors.Is(err, ErrMagicLinkExpired),
		errors.Is(err, ErrMagicLinkUsed),
		errors.Is(err, ErrSessionExpired):
		httpx.Error(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, ErrUserNotFound):
		httpx.Error(w, http.StatusNotFound, err.Error())
	default:
		httpx.Error(w, http.StatusInternalServerError, "internal error")
	}
}

// writeJSONError writes the {"code":"...","message":"..."} error shape.
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message})
}

// oauthServiceAdapter exposes the three OAuth methods that the extracted internal/oauth/handlers
// package needs.
type oauthServiceAdapter struct{ a *TheAuth }

// HasProvider reports whether the named provider is registered.
func (s oauthServiceAdapter) HasProvider(name string) bool {
	ok, _ := s.LookupProvider(context.Background(), name)
	return ok
}

// LookupProvider reports whether the named provider exists, consulting ProviderResolver when set.
func (s oauthServiceAdapter) LookupProvider(ctx context.Context, name string) (bool, error) {
	return s.a.oauthSvc.LookupProvider(ctx, name)
}

// Start delegates the /auth/providers/{name}/start flow to *TheAuth.startOAuth.
func (s oauthServiceAdapter) Start(ctx context.Context, r *http.Request, providerName, returnTo string) (internaloauth.StartResult, error) {
	return s.a.startOAuth(ctx, r, providerName, returnTo)
}

// Callback delegates the /auth/providers/{name}/callback flow to *TheAuth.callbackOAuth, discarding
// the *User return (the handler only needs the session token).
func (s oauthServiceAdapter) Callback(ctx context.Context, providerName, code, state, binding, ua, ip string) (internaloauth.CallbackResult, error) {
	res, _, err := s.a.callbackOAuth(ctx, providerName, code, state, binding, ua, ip)
	return res, err
}

// passwordServiceAdapter routes Signup, Signin and Reset through the hook-firing root forwarders.
// Calling passwordSvc directly would silently skip LifecycleHooks.
type passwordServiceAdapter struct{ a *TheAuth }

func (s passwordServiceAdapter) Signup(ctx context.Context, emailAddr, pw string) (*User, string, error) {
	return s.a.signupWithPassword(ctx, emailAddr, pw)
}

func (s passwordServiceAdapter) Signin(ctx context.Context, emailAddr, pw, userAgent, ip string) (string, *User, SigninStep, error) {
	return s.a.signinWithPassword(ctx, emailAddr, pw, userAgent, ip)
}

func (s passwordServiceAdapter) RequestReset(ctx context.Context, emailAddr string) error {
	return s.a.passwordSvc.RequestReset(ctx, emailAddr)
}

func (s passwordServiceAdapter) Reset(ctx context.Context, token, newPassword string) error {
	return s.a.resetPassword(ctx, token, newPassword)
}

// mountPasswordHandlers mounts the /email-password/* routes via internal/password/handlers.
func (a *TheAuth) mountPasswordHandlers(r chi.Router, ipLimit, emailLimit func(http.Handler) http.Handler) {
	h := passwordhandlers.New(passwordServiceAdapter{a: a}, passwordhandlers.CookieConfig{
		Name:             a.cookieName,
		SecureFlag:       a.secureCookie,
		TTL:              a.sessionTTL,
		DeviceCookieName: a.deviceCookie,
	})
	h.Mount(r, ipLimit, emailLimit)
}

// mountTOTP mounts /auth/totp/* via internal/totp/handlers. totpServiceAdapter routes
// FinishEnrollment through the hook-firing forwarder so OnMFAEnabled is never skipped.
type totpServiceAdapter struct{ a *TheAuth }

func (s totpServiceAdapter) BeginEnrollment(ctx context.Context, userID ULID, accountName string) (EnrollTOTPResult, error) {
	return s.a.BeginTOTPEnrollment(ctx, userID, accountName)
}

func (s totpServiceAdapter) FinishEnrollment(ctx context.Context, userID ULID, enrollmentID, code string) ([]string, error) {
	return s.a.FinishTOTPEnrollment(ctx, userID, enrollmentID, code)
}

func (s totpServiceAdapter) Verify(ctx context.Context, pendingSessionToken, code string) (string, Session, error) {
	_, sess, err := s.a.totpSvc.Verify(ctx, pendingSessionToken, code)
	if err != nil {
		return "", Session{}, err
	}
	return s.rotateAndFireSignin(ctx, sess)
}

func (s totpServiceAdapter) ConsumeRecoveryCode(ctx context.Context, pendingSessionToken, code string) (string, Session, error) {
	_, sess, err := s.a.totpSvc.ConsumeRecoveryCode(ctx, pendingSessionToken, code)
	if err != nil {
		return "", Session{}, err
	}
	return s.rotateAndFireSignin(ctx, sess)
}

// rotateAndFireSignin swaps the upgraded pending session for a fresh one and fires OnSignin with
// the session the client will hold. It bypasses the public forwarders so the hook fires once and
// never sees the revoked pre-rotation session.
func (s totpServiceAdapter) rotateAndFireSignin(ctx context.Context, sess Session) (string, Session, error) {
	tok, ns, err := s.a.RotateSession(ctx, sess)
	if err != nil {
		return "", Session{}, err
	}
	s.a.fireOnSigninForUserID(ctx, ns.UserID, &ns)
	return tok, ns, nil
}

func (s totpServiceAdapter) Status(ctx context.Context, userID ULID) (TOTPStatus, error) {
	return s.a.TOTPStatus(ctx, userID)
}

func (s totpServiceAdapter) RegenerateRecoveryCodes(ctx context.Context, userID ULID) ([]string, error) {
	return s.a.RegenerateRecoveryCodes(ctx, userID)
}

func (s totpServiceAdapter) Delete(ctx context.Context, userID ULID) error {
	if err := s.a.totpSvc.Delete(ctx, userID); err != nil {
		return err
	}
	if s.a.devices != nil {
		if _, err := s.a.devices.RevokeAll(ctx, userID); err != nil {
			slog.Warn("theauth: revoke trusted devices after totp removal failed", "user_id", userID.String(), "err", err.Error())
		}
	}
	return nil
}

// RememberDevice implements the optional DeviceRemember capability of the TOTP handlers.
func (s totpServiceAdapter) RememberDevice(ctx context.Context, userID ULID, userAgent, ip string) (string, time.Time, error) {
	return s.a.rememberTrustedDevice(ctx, userID, userAgent, ip)
}

func (a *TheAuth) mountTOTP(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	h := totphandlers.New(
		totpServiceAdapter{a: a},
		totphandlers.CookieConfig{
			Name:             a.cookieName,
			SecureFlag:       a.secureCookie,
			TTL:              a.sessionTTL,
			DeviceCookieName: a.deviceCookie,
		},
		func(r *http.Request) (*models.User, bool) {
			return UserFromContext(r.Context())
		},
	)
	h.Mount(r, ipLimit, a.RequireAuth(), a.RequirePendingOrFull())
}

// mountWebAuthn mounts /auth/webauthn/* via internal/webauthn/handlers. The adapter routes
// FinishRegistration through the hook-firing forwarder so OnSignup fires on a user's first
// credential.
type webauthnServiceAdapter struct{ a *TheAuth }

func (s webauthnServiceAdapter) BeginRegistration(ctx context.Context, userID ULID) (*protocol.CredentialCreation, string, error) {
	return s.a.BeginPasskeyRegistration(ctx, userID)
}

func (s webauthnServiceAdapter) FinishRegistration(ctx context.Context, userID ULID, challengeToken, name string, body io.Reader) (WebAuthnCredential, error) {
	return s.a.FinishPasskeyRegistration(ctx, userID, challengeToken, name, body)
}

func (s webauthnServiceAdapter) BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	return s.a.BeginPasskeyLogin(ctx)
}

func (s webauthnServiceAdapter) FinishLogin(ctx context.Context, challengeToken string, body io.Reader, ua, ip string) (string, Session, error) {
	return s.a.FinishPasskeyLogin(ctx, challengeToken, body, ua, ip)
}

func (s webauthnServiceAdapter) ListCredentials(ctx context.Context, userID ULID) ([]WebAuthnCredential, error) {
	return s.a.webauthnSvc.ListCredentials(ctx, userID)
}

func (s webauthnServiceAdapter) RenameCredential(ctx context.Context, id, userID ULID, name string) error {
	return s.a.webauthnSvc.RenameCredential(ctx, id, userID, name)
}

func (s webauthnServiceAdapter) DeleteCredential(ctx context.Context, id, userID ULID) error {
	return s.a.webauthnSvc.DeleteCredential(ctx, id, userID)
}

func (a *TheAuth) mountWebAuthn(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	h := webauthnhandlers.New(
		webauthnServiceAdapter{a: a},
		webauthnhandlers.SessionCookieConfig{
			Name:       a.cookieName,
			SecureFlag: a.secureCookie,
			TTL:        a.sessionTTL,
		},
		webauthnhandlers.ChallengeCookieConfig{
			Path:       a.pathPrefix + "/webauthn",
			SecureFlag: a.secureCookie,
			TTL:        a.webauthnCfg.ChallengeTTL,
		},
		func(r *http.Request) (*models.User, bool) {
			return UserFromContext(r.Context())
		},
	)
	h.Mount(r, ipLimit, a.RequireAuth())
}

// mountOAuth mounts /auth/providers/* via internal/oauth/handlers.
func (a *TheAuth) mountOAuth(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	h := oauthhandlers.New(
		oauthServiceAdapter{a: a},
		oauthhandlers.SessionCookieConfig{
			Name:       a.cookieName,
			SecureFlag: a.secureCookie,
			TTL:        a.sessionTTL,
		},
		a.postLoginRedirect,
	)
	h.Mount(r, ipLimit)
}

// mountAS mounts the OAuth 2.1 authorization server routes via internal/as/handlers. It runs only
// when AuthorizationServer is set.
func (a *TheAuth) mountAS(r chi.Router) {
	if a.as == nil {
		return
	}
	h := ashandlers.New(a.as, userFromRequest, a.dcrRegistrationTokenHashes)
	h.SetClientIP(func(r *http.Request) string { return extractClientIPTrusting(r, a.trustedProxies) })
	h.SetAuthContext(a.asAuthContext)
	h.SetSessionEnder(a.asEndSession)
	var registerLimit func(http.Handler) http.Handler
	if cap := a.as.Cfg.RegistrationRateLimitPerMinute; cap > 0 {
		registerLimit = a.RateLimitByIP(cap)
	}
	h.Mount(r, a.Authn(), registerLimit)
}

// asAuthContext reports how the request's session authenticated, for auth_time, amr and acr. The
// amr defaults to ["pwd"].
func (a *TheAuth) asAuthContext(r *http.Request) (internalas.AuthContext, bool) {
	sess, ok := SessionFromContext(r.Context())
	if !ok || sess == nil {
		return internalas.AuthContext{}, false
	}
	amr := []string{AMRPassword}
	if len(sess.AuthMethods) > 0 {
		amr = sess.AuthMethods
	}
	if fn := a.as.Cfg.SessionAMR; fn != nil {
		if got := fn(r.Context(), sess); len(got) > 0 {
			amr = got
		}
	}
	return internalas.AuthContext{AuthTime: a.lastAuthAt(sess), AMR: amr, SessionID: sess.ID.String()}, true
}

// asEndSession revokes the request's session and clears its cookie. It is the logout half of OIDC
// end_session.
func (a *TheAuth) asEndSession(w http.ResponseWriter, r *http.Request) {
	if sess, ok := SessionFromContext(r.Context()); ok && sess != nil {
		if err := a.storage.RevokeSession(r.Context(), sess.ID); err == nil {
			a.EmitAudit(r.Context(), "session.revoked", TargetRef{Type: "session", ID: sess.ID.String()}, map[string]any{"via": "oidc_end_session"})
		}
	}
	a.clearSessionCookie(w)
}
