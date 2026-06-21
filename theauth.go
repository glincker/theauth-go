package theauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/email"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// Storage is the persistence contract TheAuth depends on. Adapters live in
// sub-packages (storage/memory, storage/postgres). Defined here so that
// service code in this package can reference it without importing the
// storage sub-package (which would create an import cycle, because storage
// imports this package for the model types).
//
// The storage package re-exports this as storage.Storage so consumers can
// keep importing it from the conventional location.
type Storage interface {
	// Users
	CreateUser(ctx context.Context, u User) (User, error)
	UserByEmail(ctx context.Context, email string) (*User, error)
	UserByID(ctx context.Context, id ULID) (*User, error)
	MarkEmailVerified(ctx context.Context, userID ULID) error

	// Sessions
	CreateSession(ctx context.Context, s Session) (Session, error)
	SessionByTokenHash(ctx context.Context, hash []byte) (*Session, error)
	RevokeSession(ctx context.Context, id ULID) error
	RevokeUserSessions(ctx context.Context, userID ULID) error

	// Magic links
	CreateMagicLink(ctx context.Context, ml MagicLink) error
	ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*MagicLink, error)

	// Email + password (v0.2)
	SetUserPassword(ctx context.Context, userID ULID, passwordHash string) error
	// UserByEmailWithPassword fetches a user along with their stored PHC hash.
	// passwordHash is "" if the account exists but has never set a password
	// (e.g. magic-link-only signup). Callers should treat empty hash as
	// "no password credential available" and surface invalid_credentials.
	UserByEmailWithPassword(ctx context.Context, email string) (user *User, passwordHash string, err error)
	CreatePasswordResetToken(ctx context.Context, t PasswordResetToken) error
	ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error)

	// OAuth accounts (v0.3)
	// UpsertOAuthAccount inserts or updates the row keyed by
	// (provider, provider_user_id). Returns the resulting row so callers
	// can use the assigned ID and timestamps. Implementations must encrypt
	// any token bytes before they reach storage; this layer only persists
	// what it is given.
	UpsertOAuthAccount(ctx context.Context, a OAuthAccount) (OAuthAccount, error)
	// OAuthAccountByProviderUserID looks up the row for a provider/user
	// pair. Returns ErrStorageNotFound when no row exists.
	OAuthAccountByProviderUserID(ctx context.Context, provider, providerUserID string) (*OAuthAccount, error)

	// Sessions: v0.5 step-up additions
	// CreateSessionWithAuthLevel mints a session whose AuthLevel column is
	// set to the supplied value (typically AuthLevelPending2FA). Mirrors
	// CreateSession otherwise. CreateSession itself continues to default
	// to AuthLevelFull at the DDL layer so older callers see no change.
	CreateSessionWithAuthLevel(ctx context.Context, s Session) (Session, error)
	// UpdateSessionAuthLevel rewrites a single session's AuthLevel column.
	// Used by /auth/totp/verify to promote a pending session to full.
	UpdateSessionAuthLevel(ctx context.Context, id ULID, level string) error

	// WebAuthn (v0.5)
	InsertWebAuthnCredential(ctx context.Context, c WebAuthnCredential) (WebAuthnCredential, error)
	WebAuthnCredentialsByUserID(ctx context.Context, userID ULID) ([]WebAuthnCredential, error)
	// WebAuthnCredentialByCredentialID returns the row keyed by the raw
	// authenticator credential ID, or ErrStorageNotFound when missing.
	WebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error)
	// UpdateWebAuthnSignCount atomically writes a strictly greater sign
	// count and bumps last_used_at. Returns ErrReplayDetected when the
	// new count is not strictly greater than the stored value (the
	// canonical replay signal per WebAuthn L2 / L3). Returns
	// ErrStorageNotFound when the credential does not exist.
	UpdateWebAuthnSignCount(ctx context.Context, credentialID []byte, newCount uint32, usedAt time.Time) error
	// DeleteWebAuthnCredential removes a credential by ID, scoped to the
	// owning user. Returns ErrStorageNotFound when the row does not exist
	// or does not belong to the caller (no leak on cross-user lookup).
	DeleteWebAuthnCredential(ctx context.Context, id ULID, userID ULID) error

	// TOTP (v0.5)
	// UpsertPendingTOTPSecret writes an encrypted secret with
	// confirmed_at = NULL. Replaces any prior unconfirmed secret for the
	// same user; preserves a confirmed one untouched (re-enrollment
	// requires DeleteTOTPSecret first).
	UpsertPendingTOTPSecret(ctx context.Context, s TOTPSecret) error
	// ConfirmTOTPSecret sets confirmed_at on the user's pending secret.
	// Returns ErrStorageNotFound when no pending row exists.
	ConfirmTOTPSecret(ctx context.Context, userID ULID, at time.Time) error
	TOTPSecretByUserID(ctx context.Context, userID ULID) (*TOTPSecret, error)
	DeleteTOTPSecret(ctx context.Context, userID ULID) error

	InsertRecoveryCodes(ctx context.Context, codes []RecoveryCode) error
	// ConsumeRecoveryCode walks the user's unused codes, locates the one
	// whose hash matches via crypto.VerifyRecoveryCode, and marks it used
	// atomically. Returns ErrStorageNotFound when no matching unused code
	// exists (covers wrong code, reused code, and cross-user mismatch).
	ConsumeRecoveryCode(ctx context.Context, userID ULID, code string, at time.Time) error

	// ---------- v0.7 multi-tenancy + SAML + SCIM ----------
	// All methods below are additive; existing single-tenant deployments
	// never invoke them because the corresponding handlers are mounted
	// only when Config.Organizations / SAML / SCIM are non-nil.

	// Organizations + membership
	InsertOrganization(ctx context.Context, o Organization) (Organization, error)
	OrganizationByID(ctx context.Context, id ULID) (*Organization, error)
	OrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
	UpdateOrganization(ctx context.Context, o Organization) error
	DeleteOrganization(ctx context.Context, id ULID) error

	UpsertOrganizationMember(ctx context.Context, m OrganizationMember) error
	DeleteOrganizationMember(ctx context.Context, orgID, userID ULID) error
	OrganizationMembersByOrg(ctx context.Context, orgID ULID) ([]OrganizationMember, error)
	OrganizationsByUser(ctx context.Context, userID ULID) ([]Organization, error)
	OrganizationMemberRole(ctx context.Context, orgID, userID ULID) (string, error)

	SetSessionActiveOrganization(ctx context.Context, sessionID ULID, orgID *ULID) error

	// SAML connections and identities
	InsertSAMLConnection(ctx context.Context, c SAMLConnection) (SAMLConnection, error)
	UpdateSAMLConnectionRow(ctx context.Context, c SAMLConnection) error
	DeleteSAMLConnection(ctx context.Context, id ULID) error
	SAMLConnectionByID(ctx context.Context, id ULID) (*SAMLConnection, error)
	SAMLConnectionsByOrg(ctx context.Context, orgID ULID) ([]SAMLConnection, error)

	UpsertSAMLIdentity(ctx context.Context, i SAMLIdentity) (SAMLIdentity, error)
	SAMLIdentityByConnectionAndNameID(ctx context.Context, connectionID ULID, nameID string) (*SAMLIdentity, error)
	TouchSAMLIdentityLastLogin(ctx context.Context, id ULID, at time.Time) error

	// SCIM tokens
	InsertSCIMToken(ctx context.Context, t SCIMToken) (SCIMToken, error)
	SCIMTokenByHash(ctx context.Context, hash []byte) (*SCIMToken, error)
	SCIMTokensByOrg(ctx context.Context, orgID ULID) ([]SCIMToken, error)
	RevokeSCIMTokenByID(ctx context.Context, id ULID, at time.Time) error
	TouchSCIMTokenLastUsed(ctx context.Context, id ULID, at time.Time) error

	// SCIM user + group lookups scoped to a single organization
	ListUsersByOrganization(ctx context.Context, orgID ULID, offset, limit int, filter SCIMUserFilter) (users []User, total int, err error)
	ListGroupsByOrganization(ctx context.Context, orgID ULID, offset, limit int, filter SCIMGroupFilter) (groups []Group, total int, err error)
	UserByExternalIDInOrg(ctx context.Context, orgID ULID, externalID string) (*User, error)
	UpdateUserSCIM(ctx context.Context, u User) error

	// Groups (SCIM)
	InsertGroup(ctx context.Context, g Group) (Group, error)
	GroupByID(ctx context.Context, id ULID) (*Group, error)
	GroupByExternalIDInOrg(ctx context.Context, orgID ULID, externalID string) (*Group, error)
	UpdateGroup(ctx context.Context, g Group) error
	DeleteGroup(ctx context.Context, id ULID) error
	SetGroupMembers(ctx context.Context, groupID ULID, userIDs []ULID) error
	AddGroupMembers(ctx context.Context, groupID ULID, userIDs []ULID) error
	RemoveGroupMembers(ctx context.Context, groupID ULID, userIDs []ULID) error
	GroupMembers(ctx context.Context, groupID ULID) ([]ULID, error)
}

// Config holds the wiring for a TheAuth instance.
//
// Storage and BaseURL are required. Everything else has sensible defaults
// applied by New: SessionTTL=24h, MagicLinkTTL=15m, CookieName="theauth_session",
// EmailSender=email.Noop{}. SigningKey is reserved for future JWT signing (v0.2+);
// v0.1 uses opaque tokens and leaves the field nil.
type Config struct {
	Storage      Storage
	EmailSender  email.Sender
	BaseURL      string
	SigningKey   ed25519.PrivateKey
	SessionTTL   time.Duration
	MagicLinkTTL time.Duration
	CookieName   string
	SecureCookie bool
	// RateLimitPerIP is the per-IP per-minute budget applied to credential
	// endpoints (signup/signin/forgot/reset). Defaults to 5 when zero.
	RateLimitPerIP int
	// RateLimitPerEmail is the per-email per-minute budget applied to signin
	// + forgot. Defaults to 3 when zero.
	RateLimitPerEmail int

	// Providers is the list of OAuth providers exposed under
	// /auth/providers/{name}/start and /callback. Leave nil to disable
	// OAuth entirely (v0.1 / v0.2 behavior). Each provider's Name() must
	// be unique within the slice.
	Providers []Provider

	// EncryptionKey is the 32-byte AES-256 key used to encrypt provider
	// access/refresh tokens before they hit storage. Required when
	// len(Providers) > 0; New returns an error otherwise. Source this from
	// a secrets manager; never commit it.
	EncryptionKey []byte

	// PostLoginRedirect is where the OAuth callback handler 302s to after
	// a successful sign-in. Defaults to "/" when empty. Set to a path on
	// your own origin; cross-origin redirects are not validated here.
	PostLoginRedirect string

	// WebAuthn enables passkey registration + discoverable login when non-nil.
	// RPID and RPOrigins are mandatory per spec. Leave nil to keep v0.4 behavior.
	WebAuthn *WebAuthnConfig

	// TOTP enables time-based second-factor enrollment + verification when non-nil.
	// Requires Config.EncryptionKey (already required by v0.3 OAuth) so the stored
	// secret is encrypted at rest. New returns an error if TOTP is set without a key.
	TOTP *TOTPConfig

	// Organizations (v0.7) enables multi-tenancy when non-nil. Single-tenant
	// deployments leave this nil; organization-scoped routes (SAML connection
	// CRUD, SCIM token CRUD, /auth/orgs/*) are not mounted.
	Organizations *OrganizationsConfig

	// SAML (v0.7) enables the per-connection Service Provider routes when
	// non-nil. The SP keypair lives on the config so multi-tenant deployments
	// can rotate it centrally; every connection signs AuthnRequests with this
	// single keypair. Requires Organizations to be non-nil.
	SAML *SAMLConfig

	// SCIM (v0.7) enables the /scim/v2 endpoints when non-nil. Requires
	// Organizations to be non-nil.
	SCIM *SCIMConfig

	// AuditHook (v0.7) is invoked synchronously for every SCIM mutation and
	// every successful SAML assertion. The hook is a stub for v0.7 and
	// becomes the entry point for the real async writer in v1.0. Nil hooks
	// are a no-op; the library never blocks on this call.
	AuditHook AuditHook
}

// OrganizationsConfig is currently empty: there are no tunables for v0.7.
// The presence of a non-nil value is the signal that multi-tenancy is on.
// Future fields (default member role, invitation TTL, etc.) land here without
// breaking the existing zero-value wiring.
type OrganizationsConfig struct{}

// SAMLConfig wires the Service Provider keypair and base behavior. Per-IdP
// configuration lives in saml_connections rows, not here.
type SAMLConfig struct {
	// SPCertificatePEM and SPPrivateKeyPEM are PEM-encoded; they sign every
	// outbound AuthnRequest and identify the SP in metadata XML. New returns
	// an error if either is missing or unparseable.
	SPCertificatePEM []byte
	SPPrivateKeyPEM  []byte

	// AuthnRequestTTL caps how long an outstanding SP-initiated AuthnRequest
	// ID is tracked for replay protection. Defaults to 10 minutes.
	AuthnRequestTTL time.Duration

	// ClockSkew accepted on Conditions.NotBefore / NotOnOrAfter. Defaults to
	// 30 seconds (matches crewjam default). Some IdPs (Okta on slow clocks)
	// need 60s.
	ClockSkew time.Duration
}

// SCIMConfig wires the SCIM 2.0 endpoint behavior.
type SCIMConfig struct {
	// RequireHTTPS rejects requests whose r.TLS is nil and whose
	// X-Forwarded-Proto header is not "https". Default true. Set false only
	// when SCIM is fronted by a TLS-terminating proxy that strips the header
	// (in which case the proxy is responsible for TLS).
	RequireHTTPS bool

	// MaxPageSize caps the count parameter on list endpoints. Defaults to
	// 200. RFC 7644 section 3.4.2 lets the server enforce a maximum.
	MaxPageSize int
}

// AuditHook (v0.7) is the synchronous hook invoked for every SCIM mutation
// and every successful SAML assertion. v0.7 ships a no-op default; v1.0
// replaces this with the real async audit writer. Actor is either a SCIM
// token ID (for SCIM mutations) or a SAML connection ID (for SAML logins).
type AuditHook func(ctx context.Context, event AuditEvent)

// AuditEvent is the payload passed to AuditHook. Token plaintext is never
// included; only the hashed actor identifier and the resource id are.
type AuditEvent struct {
	Action         string
	OrganizationID ULID
	ActorID        ULID
	ResourceID     ULID
	Detail         string
	At             time.Time
}

// WebAuthnConfig wires the Relying Party identity. Field names mirror the
// upstream go-webauthn/webauthn.Config so consumers reading either set of
// docs see the same vocabulary.
type WebAuthnConfig struct {
	// RPID is the Relying Party Server ID. e.g. "glinr.com" (eTLD+1 of the
	// origin, no scheme, no port). Required.
	RPID string
	// RPDisplayName is shown by browsers and authenticators. Required.
	RPDisplayName string
	// RPOrigins is the fully qualified origins permitted to invoke the
	// API, e.g. ["https://glinr.com"]. At least one required.
	RPOrigins []string
	// ChallengeTTL caps how long the in-memory challenge session is valid.
	// Defaults to 5 minutes; challenges are single-use regardless.
	ChallengeTTL time.Duration
}

// TOTPConfig wires the second-factor TOTP behavior. Algorithm is fixed at
// SHA-1 / 30s / 6 digits for compatibility with Google Authenticator, Authy,
// 1Password, and every other mainstream authenticator app. Skew is fixed at
// one period before/after (the pquerna/otp default) to absorb client clock
// drift.
type TOTPConfig struct {
	// Issuer is shown in the authenticator app, e.g. "GLINR Quarter".
	Issuer string
	// RecoveryCodeCount defaults to 10 when zero. Each code is 10 hex chars
	// (40 bits of entropy) generated via crypto/rand.
	RecoveryCodeCount int
}

// TheAuth is the public entry point, constructed once at app start and
// shared across handlers.
type TheAuth struct {
	storage           Storage
	emailSender       email.Sender
	baseURL           string
	signingKey        ed25519.PrivateKey
	sessionTTL        time.Duration
	magicLinkTTL      time.Duration
	cookieName        string
	secureCookie      bool
	rateLimitPerIP    int
	rateLimitPerEmail int

	// OAuth (v0.3)
	providers         map[string]Provider
	encryptionKey     []byte
	postLoginRedirect string
	oauthStates       sync.Map // map[string]*oauthState
	oauthStateStop    chan struct{}

	// WebAuthn (v0.5). nil when Config.WebAuthn was not set; routes are
	// only mounted in that case.
	webauthn           *gowebauthn.WebAuthn
	webauthnCfg        *WebAuthnConfig
	webauthnChals      sync.Map // map[string]*webauthnChallenge
	webauthnStop       chan struct{}
	webauthnChalTTL    time.Duration
	pendingFailures    sync.Map // map[ULID]*pendingFailureCounter
	totpCfg            *TOTPConfig
	totpEnrollments    sync.Map // map[string]*totpEnrollment
	totpEnrollmentStop chan struct{}

	// v0.7
	orgsCfg           *OrganizationsConfig
	samlCfg           *SAMLConfig
	samlSPCert        *x509.Certificate
	samlSPKey         *rsa.PrivateKey
	samlAuthnInFlight sync.Map // map[string]time.Time -- AuthnRequest ID -> deadline
	samlAuthnStop     chan struct{}
	scimCfg           *SCIMConfig
	auditHook         AuditHook
}

// New validates the Config, applies defaults, and returns a ready TheAuth.
func New(cfg Config) (*TheAuth, error) {
	if cfg.Storage == nil {
		return nil, errors.New("theauth: Config.Storage is required")
	}
	if cfg.BaseURL == "" {
		return nil, errors.New("theauth: Config.BaseURL is required")
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 24 * time.Hour
	}
	if cfg.MagicLinkTTL == 0 {
		cfg.MagicLinkTTL = 15 * time.Minute
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "theauth_session"
	}
	if cfg.EmailSender == nil {
		cfg.EmailSender = email.Noop{}
	}
	if cfg.RateLimitPerIP <= 0 {
		cfg.RateLimitPerIP = 5
	}
	if cfg.RateLimitPerEmail <= 0 {
		cfg.RateLimitPerEmail = 3
	}

	// OAuth validation: any provider configured requires a 32-byte key, and
	// every provider name must be unique within the slice. Empty Providers
	// is fully backward compatible.
	providers := map[string]Provider{}
	if len(cfg.Providers) > 0 {
		if len(cfg.EncryptionKey) != crypto.AESKeyLen {
			return nil, errors.New("theauth: Config.EncryptionKey must be 32 bytes when Providers are configured")
		}
		for _, p := range cfg.Providers {
			if p == nil {
				return nil, errors.New("theauth: Config.Providers contains a nil entry")
			}
			name := p.Name()
			if name == "" {
				return nil, errors.New("theauth: provider returned an empty Name()")
			}
			if _, dup := providers[name]; dup {
				return nil, errors.New("theauth: duplicate provider name: " + name)
			}
			providers[name] = p
		}
	}
	if cfg.PostLoginRedirect == "" {
		cfg.PostLoginRedirect = "/"
	}

	// v0.5: WebAuthn + TOTP validation. Both blocks are optional and
	// orthogonal; consumers can wire either, both, or neither.
	var wa *gowebauthn.WebAuthn
	if cfg.WebAuthn != nil {
		if cfg.WebAuthn.RPID == "" {
			return nil, errors.New("theauth: Config.WebAuthn.RPID is required")
		}
		if len(cfg.WebAuthn.RPOrigins) == 0 {
			return nil, errors.New("theauth: Config.WebAuthn.RPOrigins must have at least one entry")
		}
		display := cfg.WebAuthn.RPDisplayName
		if display == "" {
			display = cfg.WebAuthn.RPID
		}
		w, err := gowebauthn.New(&gowebauthn.Config{
			RPID:                  cfg.WebAuthn.RPID,
			RPDisplayName:         display,
			RPOrigins:             cfg.WebAuthn.RPOrigins,
			AttestationPreference: "none", // matches passkey UX guidance; MDS3 deferred to a future config
		})
		if err != nil {
			return nil, errors.New("theauth: webauthn config: " + err.Error())
		}
		wa = w
		if cfg.WebAuthn.ChallengeTTL == 0 {
			cfg.WebAuthn.ChallengeTTL = 5 * time.Minute
		}
	}
	if cfg.TOTP != nil {
		if len(cfg.EncryptionKey) != crypto.AESKeyLen {
			return nil, errors.New("theauth: Config.EncryptionKey must be 32 bytes when TOTP is configured")
		}
		if cfg.TOTP.Issuer == "" {
			return nil, errors.New("theauth: Config.TOTP.Issuer is required")
		}
		if cfg.TOTP.RecoveryCodeCount == 0 {
			cfg.TOTP.RecoveryCodeCount = 10
		}
	}

	// v0.7 validation. SAML and SCIM both require multi-tenancy because the
	// per-connection routing keys off organization ownership.
	if cfg.SCIM != nil && cfg.Organizations == nil {
		return nil, ErrSCIMRequiresOrganizations
	}
	if cfg.SAML != nil && cfg.Organizations == nil {
		return nil, ErrSAMLRequiresOrganizations
	}
	var samlCert *x509.Certificate
	var samlKey *rsa.PrivateKey
	if cfg.SAML != nil {
		if len(cfg.SAML.SPCertificatePEM) == 0 {
			return nil, errors.New("theauth: Config.SAML.SPCertificatePEM is required")
		}
		if len(cfg.SAML.SPPrivateKeyPEM) == 0 {
			return nil, errors.New("theauth: Config.SAML.SPPrivateKeyPEM is required")
		}
		certBlock, _ := pem.Decode(cfg.SAML.SPCertificatePEM)
		if certBlock == nil {
			return nil, errors.New("theauth: Config.SAML.SPCertificatePEM is not valid PEM")
		}
		c, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, errors.New("theauth: Config.SAML.SPCertificatePEM parse: " + err.Error())
		}
		samlCert = c
		keyBlock, _ := pem.Decode(cfg.SAML.SPPrivateKeyPEM)
		if keyBlock == nil {
			return nil, errors.New("theauth: Config.SAML.SPPrivateKeyPEM is not valid PEM")
		}
		// Accept PKCS1 RSA, PKCS8 RSA, and EC-as-PKCS8 (Microsoft tooling
		// often emits PKCS8 even for RSA keys); other key types reject.
		switch keyBlock.Type {
		case "RSA PRIVATE KEY":
			k, kerr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if kerr != nil {
				return nil, errors.New("theauth: Config.SAML.SPPrivateKeyPEM PKCS1 parse: " + kerr.Error())
			}
			samlKey = k
		case "PRIVATE KEY":
			anyKey, kerr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
			if kerr != nil {
				return nil, errors.New("theauth: Config.SAML.SPPrivateKeyPEM PKCS8 parse: " + kerr.Error())
			}
			rk, ok := anyKey.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("theauth: Config.SAML.SPPrivateKeyPEM must be an RSA key")
			}
			samlKey = rk
		default:
			return nil, errors.New("theauth: Config.SAML.SPPrivateKeyPEM unrecognised PEM type: " + keyBlock.Type)
		}
		if cfg.SAML.AuthnRequestTTL == 0 {
			cfg.SAML.AuthnRequestTTL = 10 * time.Minute
		}
		if cfg.SAML.ClockSkew == 0 {
			cfg.SAML.ClockSkew = 30 * time.Second
		}
	}
	if cfg.SCIM != nil {
		if cfg.SCIM.MaxPageSize == 0 {
			cfg.SCIM.MaxPageSize = 200
		}
	}
	if cfg.AuditHook == nil {
		cfg.AuditHook = noopAuditHook
	}

	a := &TheAuth{
		storage:           cfg.Storage,
		emailSender:       cfg.EmailSender,
		baseURL:           cfg.BaseURL,
		signingKey:        cfg.SigningKey,
		sessionTTL:        cfg.SessionTTL,
		magicLinkTTL:      cfg.MagicLinkTTL,
		cookieName:        cfg.CookieName,
		secureCookie:      cfg.SecureCookie,
		rateLimitPerIP:    cfg.RateLimitPerIP,
		rateLimitPerEmail: cfg.RateLimitPerEmail,
		providers:         providers,
		encryptionKey:     cfg.EncryptionKey,
		postLoginRedirect: cfg.PostLoginRedirect,
		webauthn:          wa,
		webauthnCfg:       cfg.WebAuthn,
		totpCfg:           cfg.TOTP,
		orgsCfg:           cfg.Organizations,
		samlCfg:           cfg.SAML,
		samlSPCert:        samlCert,
		samlSPKey:         samlKey,
		scimCfg:           cfg.SCIM,
		auditHook:         cfg.AuditHook,
	}
	if len(providers) > 0 {
		a.oauthStateStop = make(chan struct{})
		go a.oauthStateGCLoop()
	}
	if wa != nil {
		a.webauthnChalTTL = cfg.WebAuthn.ChallengeTTL
		a.webauthnStop = make(chan struct{})
		go a.webauthnChallengeGCLoop()
	}
	if cfg.TOTP != nil {
		a.totpEnrollmentStop = make(chan struct{})
		go a.totpEnrollmentGCLoop()
	}
	if cfg.SAML != nil {
		a.samlAuthnStop = make(chan struct{})
		go a.samlAuthnGCLoop()
	}
	return a, nil
}

// noopAuditHook is the v0.7 default. v1.0 replaces this binding with the
// real async writer; the signature stays stable so consumer code does not
// need to change.
func noopAuditHook(_ context.Context, _ AuditEvent) {}

// Close releases background resources started by New: the OAuth state GC
// loop (v0.3) and the WebAuthn challenge / TOTP enrollment GC loops (v0.5).
// Safe to call multiple times; safe to omit in tests that don't configure
// the corresponding feature.
func (a *TheAuth) Close() {
	closeOnce := func(ch chan struct{}) {
		if ch == nil {
			return
		}
		select {
		case <-ch:
			// already closed
		default:
			close(ch)
		}
	}
	closeOnce(a.oauthStateStop)
	closeOnce(a.webauthnStop)
	closeOnce(a.totpEnrollmentStop)
	closeOnce(a.samlAuthnStop)
}
