// Package magiclink owns the request / consume flow for email-delivered
// magic-link sign-in tokens. Extracted from root service_magiclink.go in
// PR A of the 2026-06 architecture reorg.
//
// On Request the package mints a fresh token, persists its hash with a
// TTL, and emails the raw token to the user as a click-through link. On
// Consume the package atomically marks the link used, finds-or-creates the
// user, marks email verified, and issues a fresh session via the injected
// session.Issuer (so this package does not need to depend on the session
// package directly; tests inject a stub).
package magiclink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/email"
	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
)

// Storage is the minimal persistence subset this package needs. Declared
// here (not imported from root) so internal/magiclink does not import the
// root theauth package and the constructor cycle stays broken.
type Storage interface {
	CreateMagicLink(ctx context.Context, ml models.MagicLink) error
	ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*models.MagicLink, error)
	UserByEmail(ctx context.Context, email string) (*models.User, error)
	CreateUser(ctx context.Context, u models.User) (models.User, error)
	MarkEmailVerified(ctx context.Context, userID models.ULID) error
}

// SessionIssuer abstracts the session.Issue call. Allows magiclink to mint
// a session at consume time without importing internal/session (the root
// constructor wires the concrete *session.Service in).
type SessionIssuer interface {
	Issue(ctx context.Context, user models.User, userAgent, ip string) (string, models.Session, error)
}

// Service holds the dependencies needed to request and consume magic
// links. Constructed once in theauth.New.
type Service struct {
	storage  Storage
	sender   email.Sender
	baseURL  string
	ttl      time.Duration
	sessions SessionIssuer
	auditEm  audit.Emitter
}

// New constructs a magiclink Service.
func New(storage Storage, sender email.Sender, baseURL string, ttl time.Duration, sessions SessionIssuer, em audit.Emitter) *Service {
	if em == nil {
		em = audit.NoopEmitter{}
	}
	return &Service{
		storage:  storage,
		sender:   sender,
		baseURL:  baseURL,
		ttl:      ttl,
		sessions: sessions,
		auditEm:  em,
	}
}

// Request mints a magic-link token, persists its hash, and emails the raw
// token to the user as a click-through verification link. Production code
// calls this; the raw token only ever appears in the inbox.
func (s *Service) Request(ctx context.Context, emailAddr string) error {
	_, err := s.RequestForTest(ctx, emailAddr)
	return err
}

// RequestForTest is the same as Request but returns the raw token so tests
// can drive a consume flow without scraping email.
func (s *Service) RequestForTest(ctx context.Context, emailAddr string) (string, error) {
	emailAddr = strings.ToLower(strings.TrimSpace(emailAddr))
	token, err := crypto.NewToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	ml := models.MagicLink{
		ID:        ulid.New(),
		Email:     emailAddr,
		TokenHash: crypto.HashToken(token),
		ExpiresAt: now.Add(s.ttl),
		CreatedAt: now,
	}
	if err := s.storage.CreateMagicLink(ctx, ml); err != nil {
		return "", err
	}
	link := fmt.Sprintf("%s/auth/magic-link/verify?token=%s", s.baseURL, token)
	body := fmt.Sprintf("Click to sign in: %s\n\nExpires in %s.", link, s.ttl)
	if err := s.sender.Send(ctx, emailAddr, "Sign in to TheAuth", body); err != nil {
		return "", err
	}
	s.auditEm.EmitAudit(ctx, "magic_link.requested", models.TargetRef{Type: "user", ID: ml.ID.String()}, map[string]any{
		"email_hash": hashEmailForAudit(emailAddr),
	})
	slog.Info("theauth: magic link requested", "email", emailAddr)
	return token, nil
}

// Consume atomically marks a magic-link as used, finds-or-creates the
// corresponding user, marks their email verified, and issues a fresh
// session. Returns models.ErrInvalidToken for unknown tokens and
// models.ErrMagicLinkExpired when the link's TTL has elapsed.
func (s *Service) Consume(ctx context.Context, token string) (sessionToken string, user *models.User, err error) {
	ml, err := s.storage.ConsumeMagicLink(ctx, crypto.HashToken(token))
	if errors.Is(err, models.ErrStorageNotFound) {
		return "", nil, models.ErrInvalidToken
	}
	if err != nil {
		return "", nil, err
	}
	if ml.ExpiresAt.Before(time.Now()) {
		return "", nil, models.ErrMagicLinkExpired
	}
	// Find-or-create user
	u, err := s.storage.UserByEmail(ctx, ml.Email)
	if errors.Is(err, models.ErrStorageNotFound) {
		now := time.Now()
		newUser, cerr := s.storage.CreateUser(ctx, models.User{
			ID:              ulid.New(),
			Email:           ml.Email,
			EmailVerifiedAt: &now,
			CreatedAt:       now,
			UpdatedAt:       now,
		})
		if cerr != nil {
			return "", nil, cerr
		}
		u = &newUser
	} else if err != nil {
		return "", nil, err
	} else if u.EmailVerifiedAt == nil {
		// Existing user, mark verified now
		if err := s.storage.MarkEmailVerified(ctx, u.ID); err != nil {
			slog.Warn("theauth: mark email verified failed", "user_id", u.ID.String(), "err", err.Error())
		}
	}
	sessToken, _, err := s.sessions.Issue(ctx, *u, "", "")
	if err != nil {
		return "", nil, err
	}
	s.auditEm.EmitAudit(ctx, "magic_link.verified", models.TargetRef{Type: "user", ID: u.ID.String()}, nil)
	s.auditEm.EmitAudit(ctx, "user.login", models.TargetRef{Type: "user", ID: u.ID.String()}, map[string]any{
		"auth_method": "magic_link",
	})
	slog.Info("theauth: magic link consumed", "user_id", u.ID.String(), "email", u.Email)
	return sessToken, u, nil
}

// hashEmailForAudit returns sha256(lowercase(email)) hex-encoded. Inlined
// here so the package does not need to depend on the root
// theauth.HashEmailForAudit (which would form an import cycle). Identical
// formula to the root helper; do not diverge.
func hashEmailForAudit(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}
