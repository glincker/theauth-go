package theauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

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
}

// TheAuth is the public entry point — constructed once at app start and
// shared across handlers.
type TheAuth struct {
	storage      Storage
	emailSender  email.Sender
	baseURL      string
	signingKey   ed25519.PrivateKey
	sessionTTL   time.Duration
	magicLinkTTL time.Duration
	cookieName   string
	secureCookie bool
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
	return &TheAuth{
		storage:      cfg.Storage,
		emailSender:  cfg.EmailSender,
		baseURL:      cfg.BaseURL,
		signingKey:   cfg.SigningKey,
		sessionTTL:   cfg.SessionTTL,
		magicLinkTTL: cfg.MagicLinkTTL,
		cookieName:   cfg.CookieName,
		secureCookie: cfg.SecureCookie,
	}, nil
}
