package theauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/email"
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
	}
	if len(providers) > 0 {
		a.oauthStateStop = make(chan struct{})
		go a.oauthStateGCLoop()
	}
	return a, nil
}

// Close releases background resources started by New (currently: the OAuth
// state GC goroutine). Safe to call multiple times; safe to omit in tests
// that don't configure providers.
func (a *TheAuth) Close() {
	if a.oauthStateStop != nil {
		select {
		case <-a.oauthStateStop:
			// already closed
		default:
			close(a.oauthStateStop)
		}
	}
}
