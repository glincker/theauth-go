// Package magiclink owns the request and consume flow for emailed magic-link sign-in tokens.
// Request mints and emails a token; Consume atomically marks it used, finds or creates the user,
// verifies the email and issues a session through the injected SessionIssuer.
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

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/email"
	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/emailnorm"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/pathprefix"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// Storage is the minimal persistence subset this package needs. It is declared here to keep the
// constructor cycle broken.
type Storage interface {
	CreateMagicLink(ctx context.Context, ml models.MagicLink) error
	ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*models.MagicLink, error)
	UserByEmail(ctx context.Context, email string) (*models.User, error)
	CreateUser(ctx context.Context, u models.User) (models.User, error)
	MarkEmailVerified(ctx context.Context, userID models.ULID) error
}

// SessionIssuer mints a session at consume time. The root wires the concrete session service in, so
// this package does not import it.
type SessionIssuer interface {
	Issue(ctx context.Context, user models.User, userAgent, ip string) (string, models.Session, error)
}

// Service holds the dependencies needed to request and consume magic
// links. Constructed once in theauth.New.
type Service struct {
	storage  Storage
	sender   email.Sender
	baseURL  string
	prefix   string
	ttl      time.Duration
	sessions SessionIssuer
	auditEm  audit.Emitter
	norm     emailnorm.Normalizer
	gate     SignupGate
}

// SignupGate decides whether a magic link may create a new user.
type SignupGate interface {
	Begin(ctx context.Context) (done func(created *models.User), err error)
}

// SetHardening configures email canonicalization and the signup gate.
// Call before the service handles requests; gate may be nil.
func (s *Service) SetHardening(norm emailnorm.Normalizer, gate SignupGate) {
	s.norm = norm
	s.gate = gate
}

// SetPathPrefix sets the route prefix used in emailed links. Empty keeps the default.
func (s *Service) SetPathPrefix(p string) { s.prefix = pathprefix.Normalize(p) }

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

// Request mints a magic-link token, stores its hash and emails the raw token as a click-through
// link. The raw token only reaches the inbox.
func (s *Service) Request(ctx context.Context, emailAddr string) error {
	_, err := s.RequestForTest(ctx, emailAddr)
	return err
}

// RequestForTest is the same as Request but returns the raw token so tests
// can drive a consume flow without scraping email.
func (s *Service) RequestForTest(ctx context.Context, emailAddr string) (string, error) {
	emailAddr = s.norm.Normalize(emailAddr)
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
	link := fmt.Sprintf("%s%s/magic-link/verify?token=%s", s.baseURL, pathprefix.Normalize(s.prefix), token)
	body := fmt.Sprintf("Click to sign in: %s\n\nExpires in %s.", link, s.ttl)
	if err := s.sender.Send(ctx, emailAddr, "Sign in to TheAuth", body); err != nil {
		return "", err
	}
	s.auditEm.EmitAudit(ctx, "magic_link.requested", models.TargetRef{Type: "user", ID: ml.ID.String()}, map[string]any{
		"email_hash": hashEmailForAudit(emailAddr),
	})
	slog.Info("theauth: magic link requested", "email_ref", emailnorm.LogRef(emailAddr))
	return token, nil
}

// Consume atomically marks a link used, finds or creates the user, verifies the email and issues a
// session. Unknown tokens return ErrInvalidToken and expired links ErrMagicLinkExpired. created
// reports whether the user row was new, so the root can pick OnSignup or OnSignin.
func (s *Service) Consume(ctx context.Context, token string) (sessionToken string, user *models.User, created bool, err error) {
	ml, err := s.storage.ConsumeMagicLink(ctx, crypto.HashToken(token))
	if errors.Is(err, models.ErrStorageNotFound) {
		return "", nil, false, models.ErrInvalidToken
	}
	if err != nil {
		return "", nil, false, err
	}
	if ml.ExpiresAt.Before(time.Now()) {
		return "", nil, false, models.ErrMagicLinkExpired
	}
	// Find-or-create user
	u, err := s.storage.UserByEmail(ctx, ml.Email)
	if errors.Is(err, models.ErrStorageNotFound) {
		if s.gate != nil {
			done, gerr := s.gate.Begin(ctx)
			if gerr != nil {
				return "", nil, false, gerr
			}
			defer func() { done(u) }()
		}
		now := time.Now()
		newUser, cerr := s.storage.CreateUser(ctx, models.User{
			ID:              ulid.New(),
			Email:           ml.Email,
			EmailVerifiedAt: &now,
			CreatedAt:       now,
			UpdatedAt:       now,
		})
		if cerr != nil {
			return "", nil, false, cerr
		}
		u = &newUser
		created = true
	} else if err != nil {
		return "", nil, false, err
	} else if u.EmailVerifiedAt == nil {
		// Existing user, mark verified now
		if err := s.storage.MarkEmailVerified(ctx, u.ID); err != nil {
			slog.Warn("theauth: mark email verified failed", "user_id", u.ID.String(), "err", err.Error())
		}
	}
	sessToken, _, err := s.sessions.Issue(models.WithAuthMethods(ctx, models.AMREmail), *u, "", "")
	if err != nil {
		return "", nil, false, err
	}
	s.auditEm.EmitAudit(ctx, "magic_link.verified", models.TargetRef{Type: "user", ID: u.ID.String()}, nil)
	s.auditEm.EmitAudit(ctx, "user.login", models.TargetRef{Type: "user", ID: u.ID.String()}, map[string]any{
		"auth_method": "magic_link",
	})
	slog.Info("theauth: magic link consumed", "user_id", u.ID.String())
	return sessToken, u, created, nil
}

// hashEmailForAudit matches the root HashEmailForAudit formula. It is duplicated to avoid an import
// cycle; keep the two identical.
func hashEmailForAudit(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}
