package theauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
)

// requestMagicLink mints a magic-link token, persists its hash, and emails
// the raw token to the user as a click-through verification link.
// Production code calls this — the raw token only ever appears in the inbox.
func (a *TheAuth) requestMagicLink(ctx context.Context, emailAddr string) error {
	_, err := a.requestMagicLinkForTest(ctx, emailAddr)
	return err
}

// requestMagicLinkForTest is the same as requestMagicLink but returns the
// raw token so tests can drive a consume flow without scraping email.
// Production code calls requestMagicLink; the token only ever appears in
// the user's inbox.
func (a *TheAuth) requestMagicLinkForTest(ctx context.Context, emailAddr string) (string, error) {
	emailAddr = strings.ToLower(strings.TrimSpace(emailAddr))
	token, err := crypto.NewToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	ml := MagicLink{
		ID:        ulid.New(),
		Email:     emailAddr,
		TokenHash: crypto.HashToken(token),
		ExpiresAt: now.Add(a.magicLinkTTL),
		CreatedAt: now,
	}
	if err := a.storage.CreateMagicLink(ctx, ml); err != nil {
		return "", err
	}
	link := fmt.Sprintf("%s/auth/magic-link/verify?token=%s", a.baseURL, token)
	body := fmt.Sprintf("Click to sign in: %s\n\nExpires in %s.", link, a.magicLinkTTL)
	if err := a.emailSender.Send(ctx, emailAddr, "Sign in to TheAuth", body); err != nil {
		return "", err
	}
	a.EmitAudit(ctx, "magic_link.requested", TargetRef{Type: "user", ID: ml.ID.String()}, map[string]any{
		"email_hash": HashEmailForAudit(emailAddr),
	})
	slog.Info("theauth: magic link requested", "email", emailAddr)
	return token, nil
}

// consumeMagicLink atomically marks a magic-link as used, finds-or-creates
// the corresponding user, marks their email verified, and issues a fresh
// session. Returns ErrInvalidToken for unknown tokens and ErrMagicLinkExpired
// when the link's TTL has elapsed.
func (a *TheAuth) consumeMagicLink(ctx context.Context, token string) (sessionToken string, user *User, err error) {
	ml, err := a.storage.ConsumeMagicLink(ctx, crypto.HashToken(token))
	if errors.Is(err, ErrStorageNotFound) {
		return "", nil, ErrInvalidToken
	}
	if err != nil {
		return "", nil, err
	}
	if ml.ExpiresAt.Before(time.Now()) {
		return "", nil, ErrMagicLinkExpired
	}
	// Find-or-create user
	u, err := a.storage.UserByEmail(ctx, ml.Email)
	if errors.Is(err, ErrStorageNotFound) {
		now := time.Now()
		newUser, cerr := a.storage.CreateUser(ctx, User{
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
		if err := a.storage.MarkEmailVerified(ctx, u.ID); err != nil {
			slog.Warn("theauth: mark email verified failed", "user_id", u.ID.String(), "err", err.Error())
		}
	}
	sessToken, _, err := a.issueSession(ctx, *u, "", "")
	if err != nil {
		return "", nil, err
	}
	a.EmitAudit(ctx, "magic_link.verified", TargetRef{Type: "user", ID: u.ID.String()}, nil)
	a.EmitAudit(ctx, "user.login", TargetRef{Type: "user", ID: u.ID.String()}, map[string]any{
		"auth_method": "magic_link",
	})
	slog.Info("theauth: magic link consumed", "user_id", u.ID.String(), "email", u.Email)
	return sessToken, u, nil
}
