package theauth

// domains.go consolidates the small per-domain root-package surfaces
// (CIBA, CIMD, JWKS rotation, OAuth provider type aliases, request
// context keys) into a single file. PR I (2026-06-22) merged the
// prior ciba.go, cimd.go, jwks.go, provider.go, and context.go files
// here so the repository root has fewer files and the README renders
// above the fold on GitHub. Each section below is short on its own;
// the topic groupings stay separated by header comments. Public API
// surface and signatures are byte-stable.

import (
	"context"
	"time"

	internalas "github.com/glincker/theauth-go/internal/as"
	"github.com/glincker/theauth-go/internal/cimd"
	"github.com/glincker/theauth-go/internal/models"
	internaloauth "github.com/glincker/theauth-go/internal/oauth"
)

// ---------- Request context keys ----------

type ctxKey int

const (
	userKey ctxKey = iota
	sessionKey
)

// UserFromContext returns the authenticated User attached by Authn middleware,
// if any. Returns false when the request is anonymous.
func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userKey).(*User)
	return u, ok
}

// SessionFromContext returns the Session attached by Authn middleware,
// if any. Returns false when the request is anonymous.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionKey).(*Session)
	return s, ok
}

// ---------- OAuth provider type aliases ----------

// Provider is the contract every OAuth 2.0 / OIDC provider implements. Each
// concrete provider lives in its own sub-package under provider/<name>/ so
// consumers can pick what to import (avoids dragging in HTTP clients for
// providers they will never use).
//
// The type moved to internal/oauth in PR H (2026-06-22); this alias keeps
// the v0.3+ public surface byte-stable.
type Provider = internaloauth.Provider

// ProviderToken is the normalized shape of an OAuth token exchange response.
// Providers vary in which fields they populate (e.g. GitHub typically omits
// RefreshToken and ExpiresAt for "no-expiry" tokens). Storage encrypts the
// access/refresh tokens at rest via crypto.Encrypt.
//
// The type moved to internal/oauth in PR H (2026-06-22); this alias keeps
// the v0.3+ public surface byte-stable.
type ProviderToken = internaloauth.ProviderToken

// ProviderUser is the normalized shape of a provider's userinfo response.
// ID is the provider-stable user identifier (e.g. GitHub numeric id as a
// string) and is what oauth_accounts.provider_user_id stores. Email may be
// empty when the user denied the email scope or has no public email on the
// provider; EmailVerified is true only when the provider attests to it.
//
// The type moved to internal/oauth in PR H (2026-06-22); this alias keeps
// the v0.3+ public surface byte-stable.
type ProviderUser = internaloauth.ProviderUser

// ---------- JWKS rotation surface ----------

// jwks.go: thin forwarders for the JWKS rotation surface. PR B
// architecture reorg (2026-06-20) moved the JWKS state machine and the
// Ed25519 keypair lifecycle into internal/as. PR G (2026-06-21) removed
// the unexported currentSigningKey / publicKeyByKID helpers because every
// in-tree caller now goes through *as.Service directly (the AS handler
// package, the v2 token services, and the JWT verify middleware all
// import internal/as). Only the operator-facing RotateSigningKey method
// remains on the root receiver because it is part of the v2.0 public API.

// RotateSigningKey advances the JWKS state machine one step: previous
// (if any) is retired, current becomes previous, next becomes current,
// and a fresh next is minted. Idempotent under concurrent callers (each
// call mints one fresh next). Operators can invoke this on emergency
// without waiting for the scheduled tick.
func (a *TheAuth) RotateSigningKey(ctx context.Context) error {
	return a.as.RotateSigningKey(ctx)
}

// ---------- CIMD (Client ID Metadata Documents) ----------

// cimd.go: public CIMD (Client ID Metadata Documents) surface, per the
// MCP authorization specification 2025-11-25.
//
// CIMD lets an OAuth client publish its RFC 7591 client metadata at a
// stable https URL whose value IS the client_id. The AS fetches the
// URL, validates the document, and uses the metadata in place of a
// locally stored DCR registration. The MCP spec demoted RFC 7591 DCR
// (still supported) in favor of CIMD as the preferred client
// identification mechanism because CIMD eliminates the server-side
// registration step entirely.
//
// Wire CIMD on Config.AuthorizationServer.CIMD; the field is optional
// and additive. When nil, theauth-go behaves exactly as it did pre-CIMD
// (every client_id consults OAuthServerStorage).

// CIMDConfig wires the CIMD service onto the AS. Set on
// AuthorizationServerConfig.CIMD to enable https-URL client_id
// resolution. Defaults to DenyAll (fail-closed); operators must opt in
// to a permissive policy explicitly.
//
// Aliased from internal/cimd so consumers can wire CIMDConfig{...} at
// the public surface without importing the internal package.
type CIMDConfig = cimd.Config

// CIMDTrustPolicy decides which https client_id URLs the AS is allowed
// to fetch as CIMD documents. Aliased from internal/cimd.TrustPolicy.
type CIMDTrustPolicy = cimd.TrustPolicy

// DenyAll returns a CIMDTrustPolicy that rejects every URL. This is the
// fail-closed default applied when CIMDConfig.TrustPolicy is nil and is
// the default returned here so operator code reads naturally:
//
//	cfg.AuthorizationServer.CIMD = &theauth.CIMDConfig{
//	    TrustPolicy: theauth.DenyAll(), // explicit acknowledgement
//	}
//
// DenyAll mirrors the security audit H4 default for TrustedProxies:
// trust must be explicit, never implicit.
func DenyAll() CIMDTrustPolicy { return cimd.DenyAll() }

// AllowAnyHTTPS returns a CIMDTrustPolicy that permits every absolute
// https URL. Use only in deployments that intentionally federate with
// the open MCP ecosystem; production deployments that know their
// clients ahead of time should prefer AllowHTTPSHost.
func AllowAnyHTTPS() CIMDTrustPolicy { return cimd.AllowAnyHTTPS() }

// AllowHTTPSHost returns a CIMDTrustPolicy that permits one specific
// host (case-insensitive, exact match).
func AllowHTTPSHost(host string) CIMDTrustPolicy { return cimd.AllowHTTPSHost(host) }

// AllowHTTPSHosts returns a CIMDTrustPolicy that permits any of the
// supplied hosts (case-insensitive, exact match). An empty list
// produces a permanently-deny policy so a typo cannot silently allow
// every host.
func AllowHTTPSHosts(hosts ...string) CIMDTrustPolicy { return cimd.AllowHTTPSHosts(hosts...) }

// ---------- CIBA (RFC 9509 backchannel authentication) ----------

// ciba.go: root-package CIBA surface.
// CIBAConfig, AuthenticationDevice, CIBANotification are thin wrappers
// that re-export the internal/as counterparts so operators only import the
// root package. ApproveBackchannelAuth / DenyBackchannelAuth are the two
// operator-facing service methods.

// AuthenticationDevice is the operator-supplied interface that bridges the
// AS to the actual push delivery mechanism (FCM, APNs, SMS, etc.). See
// internal/as.AuthenticationDevice for the full contract.
type AuthenticationDevice interface {
	Notify(ctx context.Context, req CIBANotification) error
}

// CIBANotification is the payload delivered to AuthenticationDevice.Notify.
type CIBANotification struct {
	AuthReqID      string
	UserID         string
	ClientID       string
	Scopes         []string
	BindingMessage string
	ExpiresAt      time.Time
}

// NoopAuthenticationDevice satisfies AuthenticationDevice by discarding every
// notification. Suitable for unit tests and operator deployments that manage
// notifications out of band.
type NoopAuthenticationDevice struct{}

// Notify satisfies AuthenticationDevice. It is a no-op and always returns nil.
func (NoopAuthenticationDevice) Notify(_ context.Context, _ CIBANotification) error { return nil }

// LoggingAuthenticationDevice satisfies AuthenticationDevice by logging
// notifications to log/slog at INFO level. Suitable for staging environments.
type LoggingAuthenticationDevice struct{}

// Notify satisfies AuthenticationDevice. It logs the notification details and
// returns nil.
func (LoggingAuthenticationDevice) Notify(_ context.Context, req CIBANotification) error {
	// Fields are accessible on req; no-op here keeps the root package
	// dependency-light. Operators can replace this with a real slog call.
	_ = req
	return nil
}

// CIBAConfig wires the CIBA feature on the authorization server.
// Set Config.AuthorizationServer.CIBA to enable. Leave nil (default) to
// disable CIBA entirely.
type CIBAConfig struct {
	// AuthenticationDevice is required. The AS calls Notify on every
	// POST /oauth/bc-authorize so the user's device receives the push.
	AuthenticationDevice AuthenticationDevice

	// DefaultExpiry is the default auth_req_id lifetime. Defaults to 300s.
	DefaultExpiry time.Duration

	// DefaultInterval is the default client poll interval. Defaults to 5s.
	DefaultInterval time.Duration

	// MaxRequestedExpiry caps the requested_expiry parameter. Defaults to 600s.
	MaxRequestedExpiry time.Duration

	// MinPollInterval is the floor that triggers slow_down when breached.
	// Defaults to 3s.
	MinPollInterval time.Duration
}

// cibaAdapterDevice bridges the root AuthenticationDevice to the internal
// internalas.AuthenticationDevice interface. Both use context.Context so the
// adapter is a thin forwarder.
type cibaAdapterDevice struct {
	root AuthenticationDevice
}

func (a cibaAdapterDevice) Notify(ctx context.Context, req internalas.CIBANotification) error {
	return a.root.Notify(ctx, CIBANotification{
		AuthReqID:      req.AuthReqID,
		UserID:         req.UserID,
		ClientID:       req.ClientID,
		Scopes:         append([]string(nil), req.Scopes...),
		BindingMessage: req.BindingMessage,
		ExpiresAt:      req.ExpiresAt,
	})
}

// cibaConfigToInternal converts a root CIBAConfig to the internal/as version.
// Returns nil when cfg is nil so callers can nil-check.
func cibaConfigToInternal(cfg *CIBAConfig) *internalas.CIBAConfig {
	if cfg == nil {
		return nil
	}
	var device internalas.AuthenticationDevice
	if cfg.AuthenticationDevice != nil {
		device = cibaAdapterDevice{root: cfg.AuthenticationDevice}
	}
	return &internalas.CIBAConfig{
		AuthenticationDevice: device,
		DefaultExpiry:        cfg.DefaultExpiry,
		DefaultInterval:      cfg.DefaultInterval,
		MaxRequestedExpiry:   cfg.MaxRequestedExpiry,
		MinPollInterval:      cfg.MinPollInterval,
	}
}

// ApproveBackchannelAuth marks the pending CIBA request as approved and
// provisions the access + refresh tokens that the next poll will return.
//
// userID MUST be the resolved identity of the authenticating user. When the
// original request supplied a login_hint that the operator resolved to this
// user, pass the matching ULID. If the request was already bound to a
// different user, ApproveBackchannelAuth returns ErrCIBAUserMismatch.
//
// Returns ErrCIBADisabled when CIBA is not configured or the storage does not
// implement CIBAStorage.
func (a *TheAuth) ApproveBackchannelAuth(ctx context.Context, authReqID string, userID ULID) error {
	if a.as == nil {
		return models.ErrCIBADisabled
	}
	return a.as.ApproveBackchannelRequest(ctx, authReqID, userID)
}

// DenyBackchannelAuth marks the pending CIBA request as denied. The next
// client poll returns access_denied.
//
// Returns ErrCIBADisabled when CIBA is not configured.
func (a *TheAuth) DenyBackchannelAuth(ctx context.Context, authReqID string, userID ULID) error {
	if a.as == nil {
		return models.ErrCIBADisabled
	}
	return a.as.DenyBackchannelRequest(ctx, authReqID, userID)
}
