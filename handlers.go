package theauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	ashandlers "github.com/glincker/theauth-go/internal/as/handlers"
	"github.com/glincker/theauth-go/internal/models"
	oauthhandlers "github.com/glincker/theauth-go/internal/oauth/handlers"
	passwordhandlers "github.com/glincker/theauth-go/internal/password/handlers"
	totphandlers "github.com/glincker/theauth-go/internal/totp/handlers"
	webauthnhandlers "github.com/glincker/theauth-go/internal/webauthn/handlers"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
)

// Mount wires TheAuth's HTTP routes onto the supplied chi router under /auth.
// Routes:
//
//	POST   /auth/magic-link                       request a magic link
//	GET    /auth/magic-link/verify                consume a magic link, set session cookie
//	POST   /auth/email-password/signup            create user with email + password (rate-limited)
//	POST   /auth/email-password/signin            sign in with email + password (rate-limited)
//	POST   /auth/email-password/forgot            request a password reset link (rate-limited)
//	POST   /auth/email-password/reset             consume a reset token + set new password (rate-limited)
//	GET    /auth/me                               return the authenticated user (RequireAuth)
//	DELETE /auth/sessions/current                 revoke the current session (RequireAuth)
//
// Default rate limits: 5/min per source IP on every credential endpoint, plus
// 3/min per email on signin + forgot (most attack-surface). All limits are
// in-memory + per-process; replace at the LB layer for multi-instance deploys.
func (a *TheAuth) Mount(r chi.Router) {
	// Build limiter middlewares once so the same buckets persist across all
	// routes mounted at this point. Re-mounting builds a fresh set.
	ipLimit := a.RateLimitByIP(a.rateLimitPerIP)
	emailLimit := a.RateLimitByEmail(a.rateLimitPerEmail)

	r.Route("/auth", func(r chi.Router) {
		// security re-audit L1 (2026-06-22): /auth/magic-link was unrate-limited,
		// allowing enumeration of registered email addresses. Apply the same
		// per-IP and per-email caps used by the password endpoints.
		r.With(ipLimit, emailLimit).Post("/magic-link", a.handleMagicLinkRequest)
		r.Get("/magic-link/verify", a.handleMagicLinkVerify)

		r.Route("/email-password", func(r chi.Router) {
			a.mountPasswordHandlers(r, ipLimit, emailLimit)
		})

		// OAuth providers (v0.3). Only mounted when at least one provider
		// is registered; the routes 404 cleanly otherwise.
		if len(a.providers) > 0 {
			a.mountOAuth(r, ipLimit)
		}

		// WebAuthn passkeys (v0.5). Mounted only when Config.WebAuthn is set.
		if a.webauthnCfg != nil {
			a.mountWebAuthn(r, ipLimit)
		}

		// TOTP 2FA (v0.5). Mounted only when Config.TOTP is set.
		if a.totpCfg != nil {
			a.mountTOTP(r, ipLimit)
		}

		// Multi-tenancy (v0.7). Mounted only when Config.Organizations is
		// set; the SAML connection CRUD and SCIM token CRUD subroutes hang
		// off the org tree.
		if a.orgsCfg != nil {
			a.mountOrganizations(r)
		}
		// SAML flow endpoints (v0.7). Mounted only when Config.SAML is
		// set; per-organization SAML connection CRUD lives under
		// /auth/orgs/{orgId}/saml/connections.
		if a.samlCfg != nil {
			a.mountSAML(r)
		}

		r.With(a.RequireAuth()).Delete("/sessions/current", a.handleSessionDelete)
		r.With(a.RequireAuth()).Get("/me", a.handleMe)
	})

	// SCIM 2.0 resource endpoints (v0.7). Mounted at /scim/v2/ rather than
	// under /auth so the standard SCIM URL prefix is preserved.
	if a.scimCfg != nil {
		a.mountSCIM(r)
	}

	// Admin API (v1.0). Mounted at /admin/v1/* (or AdminConfig.PathPrefix)
	// only when Config.Admin is non-nil. Requires RBAC (validated in New).
	if a.adminCfg != nil {
		a.mountAdmin(r)
	}

	// OAuth 2.1 authorization server (v2.0 phase 1 + 2). Mounted at
	// /.well-known/* and /oauth/* only when Config.AuthorizationServer is
	// non-nil. Phase 3 + 4 (agent identity, delegation, token exchange) land
	// in subsequent PRs.
	if a.as != nil {
		a.mountAS(r)
	}

	// End-user /account UX (v2.0 phase 6). Session-gated; mounted only when
	// AccountUX is true (which already requires AgentIdentity at New time).
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
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	addr, err := mail.ParseAddress(body.Email)
	if err != nil {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(addr.Address))
	if err := a.requestMagicLink(r.Context(), email); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"sent":true}`))
}

func (a *TheAuth) handleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
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
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(user)
}

func (a *TheAuth) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	sess, ok := SessionFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := a.storage.RevokeSession(r.Context(), sess.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
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
	// Prefer the new TheAuthError code mapping when available, gives callers
	// a stable Code field in the response body for programmatic handling.
	var te *TheAuthError
	if errors.As(err, &te) {
		switch te.Code {
		case CodeWeakPassword:
			writeJSONError(w, http.StatusBadRequest, te.Code, te.Message)
		case CodeEmailTaken:
			writeJSONError(w, http.StatusConflict, te.Code, te.Message)
		case CodeInvalidCredentials:
			writeJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		case CodeRateLimited:
			writeJSONError(w, http.StatusTooManyRequests, te.Code, te.Message)
		case CodePasswordResetExpired, CodePasswordResetInvalid:
			writeJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		case CodeInvalidTOTP, CodeWebAuthn:
			// 401 because the supplied factor is invalid; 400 would imply
			// a malformed request, which we already screened for above.
			writeJSONError(w, http.StatusUnauthorized, te.Code, te.Message)
		case CodeAlreadyEnrolled:
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
		http.Error(w, err.Error(), http.StatusUnauthorized)
	case errors.Is(err, ErrUserNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// writeJSONError emits the v0.2+ error response shape: {"code":"...","message":"..."}.
// Old (v0.1) error responses still use plain-text http.Error for backward compat.
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message})
}

// mounts_extracted.go consolidates the five thinnest PR-E / PR-F mount
// forwarders: password, TOTP, WebAuthn, OAuth provider (the
// /auth/providers/* tree), and the OAuth 2.1 authorization server
// (.well-known + /oauth/*). PR G (2026-06-21) merged the previous
// handlers_password.go, handlers_totp.go, handlers_webauthn.go,
// handlers_oauth.go, and handlers_oauth_server.go files here so the root
// package presents one place for the small chi.Router wiring shims that
// instantiate the extracted internal/<flow>/handlers packages. No
// behaviour change; route paths and middleware chains are byte-stable
// with v2.0. Larger mount files that carry substantive service adapters
// (account, admin, admin_agents, organizations, saml, scim) stay in
// their own files.

// oauthServiceAdapter implements internal/oauth/handlers.Service on top
// of the root *TheAuth, exposing only the three methods the extracted
// handler needs. The OAuth service itself still lives in root
// (service_oauth.go); a future PR can extract it into internal/oauth
// like PR D did for password / totp / webauthn / saml.
type oauthServiceAdapter struct{ a *TheAuth }

// HasProvider reports whether the named provider is registered.
func (s oauthServiceAdapter) HasProvider(name string) bool {
	_, ok := s.a.providers[name]
	return ok
}

// Start delegates the /auth/providers/{name}/start flow to
// *TheAuth.startOAuth.
func (s oauthServiceAdapter) Start(ctx context.Context, providerName string) (string, string, error) {
	return s.a.startOAuth(ctx, providerName)
}

// Callback delegates the /auth/providers/{name}/callback flow to
// *TheAuth.callbackOAuth, discarding the *User return (the handler
// only needs the session token).
func (s oauthServiceAdapter) Callback(ctx context.Context, providerName, code, state, ua, ip string) (string, error) {
	tok, _, err := s.a.callbackOAuth(ctx, providerName, code, state, ua, ip)
	return tok, err
}

// passwordServiceAdapter implements internal/password/handlers.Service on
// top of the root *TheAuth so Signup/Signin/Reset dispatch through the
// hook-firing root forwarders (signupWithPassword, signinWithPassword,
// resetPassword) instead of calling passwordSvc directly, which would
// silently skip LifecycleHooks (OnSignup, OnSignin, OnPasswordChange).
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

// mountPasswordHandlers wires /email-password/* subroutes via the
// extracted internal/password/handlers package. PR E architecture
// reorg (2026-06-20) moved the four endpoints to that package; this
// thin coordinator is what the root Mount calls.
func (a *TheAuth) mountPasswordHandlers(r chi.Router, ipLimit, emailLimit func(http.Handler) http.Handler) {
	h := passwordhandlers.New(passwordServiceAdapter{a: a}, passwordhandlers.CookieConfig{
		Name:       a.cookieName,
		SecureFlag: a.secureCookie,
		TTL:        a.sessionTTL,
	})
	h.Mount(r, ipLimit, emailLimit)
}

// mountTOTP wires /auth/totp/* under r via the extracted
// internal/totp/handlers package. PR E architecture reorg
// (2026-06-20) moved the five endpoints to that package; the root
// keeps this thin coordinator so handlers.go is the single Mount
// caller.
// totpServiceAdapter implements internal/totp/handlers.Service on top of
// the root *TheAuth so FinishEnrollment dispatches through the
// hook-firing root forwarder (FinishTOTPEnrollment) instead of calling
// totpSvc directly, which would silently skip LifecycleHooks.OnMFAEnabled.
type totpServiceAdapter struct{ a *TheAuth }

func (s totpServiceAdapter) BeginEnrollment(ctx context.Context, userID ULID, accountName string) (EnrollTOTPResult, error) {
	return s.a.BeginTOTPEnrollment(ctx, userID, accountName)
}

func (s totpServiceAdapter) FinishEnrollment(ctx context.Context, userID ULID, enrollmentID, code string) ([]string, error) {
	return s.a.FinishTOTPEnrollment(ctx, userID, enrollmentID, code)
}

func (s totpServiceAdapter) Verify(ctx context.Context, pendingSessionToken, code string) (string, Session, error) {
	return s.a.VerifyTOTP(ctx, pendingSessionToken, code)
}

func (s totpServiceAdapter) ConsumeRecoveryCode(ctx context.Context, pendingSessionToken, code string) (string, Session, error) {
	return s.a.ConsumeRecoveryCode(ctx, pendingSessionToken, code)
}

func (s totpServiceAdapter) Delete(ctx context.Context, userID ULID) error {
	return s.a.totpSvc.Delete(ctx, userID)
}

func (a *TheAuth) mountTOTP(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	h := totphandlers.New(
		totpServiceAdapter{a: a},
		totphandlers.CookieConfig{
			Name:       a.cookieName,
			SecureFlag: a.secureCookie,
			TTL:        a.sessionTTL,
		},
		func(r *http.Request) (*models.User, bool) {
			return UserFromContext(r.Context())
		},
	)
	h.Mount(r, ipLimit, a.RequireAuth(), a.RequirePendingOrFull())
}

// mountWebAuthn wires /auth/webauthn/* under r via the extracted
// internal/webauthn/handlers package. PR E architecture reorg
// (2026-06-20) moved the six endpoints to that package; the root
// keeps this thin coordinator so handlers.go is the single Mount
// caller.
// webauthnServiceAdapter implements internal/webauthn/handlers.Service on
// top of the root *TheAuth so FinishRegistration dispatches through the
// hook-firing root forwarder (FinishPasskeyRegistration) instead of
// calling webauthnSvc directly, which would silently skip
// LifecycleHooks.OnSignup on a user's first credential.
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
			SecureFlag: a.secureCookie,
			TTL:        a.webauthnCfg.ChallengeTTL,
		},
		func(r *http.Request) (*models.User, bool) {
			return UserFromContext(r.Context())
		},
	)
	h.Mount(r, ipLimit, a.RequireAuth())
}

// mountOAuth wires /auth/providers/* under r via the extracted
// internal/oauth/handlers package. PR E architecture reorg
// (2026-06-20) moved the two endpoints to that package; the root keeps
// this thin coordinator so handlers.go is the single Mount caller.
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

// mountAS wires the OAuth 2.1 authorization server routes (.well-known
// + /oauth/*) via the extracted internal/as/handlers package. Only
// called when Config.AuthorizationServer is non-nil (and therefore a.as
// is non-nil). PR F architecture reorg (2026-06-20) moved the AS HTTP
// surface and the scopeSplit helper there.
func (a *TheAuth) mountAS(r chi.Router) {
	if a.as == nil {
		return
	}
	h := ashandlers.New(a.as, userFromRequest, a.dcrRegistrationTokenHashes)
	var registerLimit func(http.Handler) http.Handler
	if cap := a.as.Cfg.RegistrationRateLimitPerMinute; cap > 0 {
		registerLimit = a.RateLimitByIP(cap)
	}
	h.Mount(r, a.Authn(), registerLimit)
}
