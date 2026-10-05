// Package session owns the Issue / Validate primitives for opaque
// session tokens. Extracted from root service_session.go in PR A of the
// 2026-06 architecture reorg.
//
// Tokens themselves are produced by crypto.NewToken and only the sha256
// hash is persisted; the raw token is returned to the caller exactly once
// (typically dropped into a Secure HttpOnly cookie). validate looks up by
// hash, rejects expired or revoked rows, and returns the bound user.
package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// Storage is the minimal persistence subset this package needs. Declared
// here (not imported from root) so that internal/session does not import
// github.com/glincker/theauth-go/v2, which would form an import cycle with the
// root constructor.
//
// Any type satisfying these three methods (notably the root theauth.Storage
// interface) is a valid argument to New. Duck-typed against the larger
// root contract by design.
type Storage interface {
	CreateSession(ctx context.Context, s models.Session) (models.Session, error)
	SessionByTokenHash(ctx context.Context, hash []byte) (*models.Session, error)
	UserByID(ctx context.Context, id models.ULID) (*models.User, error)
}

// Service holds the dependencies needed to issue and validate sessions.
// Constructed once in theauth.New and reused for the lifetime of the
// process.
type Service struct {
	storage Storage
	ttl     time.Duration
	policy  Policy
	gate    touchGate
}

// Toucher persists a session's last-seen time.
type Toucher interface {
	TouchSession(ctx context.Context, id models.ULID, at time.Time) error
}

// Revoker revokes one session by id.
type Revoker interface {
	RevokeSession(ctx context.Context, id models.ULID) error
}

// CredentialChecker reports whether the upstream credential a session is tied
// to is still valid. It returns models.ErrCredentialRevoked when it is not;
// any other error is treated as transient and fails the validation closed.
type CredentialChecker interface {
	CheckCredential(ctx context.Context, credentialID string) error
}

// Policy configures idle timeout, last-seen throttling and credential
// re-checks. The zero value keeps the original absolute-TTL-only behavior.
type Policy struct {
	IdleTimeout   time.Duration
	TouchInterval time.Duration
	Toucher       Toucher
	Revoker       Revoker
	Credentials   CredentialChecker
}

// SetPolicy installs the policy. Call before the Service is shared.
func (s *Service) SetPolicy(p Policy) { s.policy = p }

// touchGate admits at most one last-seen write per session per interval in
// this process, so concurrent requests do not each write.
type touchGate struct {
	mu   sync.Mutex
	last map[models.ULID]time.Time
}

func (g *touchGate) allow(id models.ULID, now time.Time, interval time.Duration) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.last == nil {
		g.last = make(map[models.ULID]time.Time)
	}
	if t, ok := g.last[id]; ok && now.Sub(t) < interval {
		return false
	}
	g.last[id] = now
	if len(g.last) > 4096 {
		for k, t := range g.last {
			if now.Sub(t) >= interval {
				delete(g.last, k)
			}
		}
	}
	return true
}

// IssueOptions customizes Service.IssueWith.
type IssueOptions struct {
	UserAgent    string
	IP           string
	CredentialID string
	// TTL overrides the service default when positive.
	TTL time.Duration
}

// New constructs a session Service.
func New(storage Storage, ttl time.Duration) *Service {
	return &Service{storage: storage, ttl: ttl}
}

// Issue mints a fresh opaque token, stores its sha256 hash with a new
// Session row, and returns the raw token. The raw token is what the caller
// puts in a cookie / sends to the user; the hash is what's persisted.
func (s *Service) Issue(ctx context.Context, user models.User, userAgent, ip string) (token string, sess models.Session, err error) {
	return s.IssueWith(ctx, user, IssueOptions{UserAgent: userAgent, IP: ip})
}

// IssueWith is Issue with per-session options.
func (s *Service) IssueWith(ctx context.Context, user models.User, opts IssueOptions) (token string, sess models.Session, err error) {
	token, err = crypto.NewToken()
	if err != nil {
		return "", models.Session{}, err
	}
	now := time.Now()
	ttl := s.ttl
	if opts.TTL > 0 {
		ttl = opts.TTL
	}
	sess = models.Session{
		ID:           ulid.New(),
		UserID:       user.ID,
		TokenHash:    crypto.HashToken(token),
		UserAgent:    opts.UserAgent,
		IP:           opts.IP,
		CreatedAt:    now,
		LastSeenAt:   now,
		ExpiresAt:    now.Add(ttl),
		CredentialID: opts.CredentialID,
	}
	sess, err = s.storage.CreateSession(ctx, sess)
	if err != nil {
		return "", models.Session{}, err
	}
	slog.Info("theauth: session issued", "user_id", sess.UserID.String(), "session_id", sess.ID.String())
	return token, sess, nil
}

// Validate looks up a session by the hash of the supplied token, verifies
// it is not expired or revoked, and returns the session and its user.
// Returns models.ErrInvalidToken for missing/unknown tokens and
// models.ErrSessionExpired for expired or revoked sessions.
func (s *Service) Validate(ctx context.Context, token string) (*models.Session, *models.User, error) {
	return s.validate(ctx, token, true)
}

// Check is Validate without the last-seen update, for liveness probes such as
// long-lived stream re-checks that must not count as user activity.
func (s *Service) Check(ctx context.Context, token string) (*models.Session, *models.User, error) {
	return s.validate(ctx, token, false)
}

func (s *Service) validate(ctx context.Context, token string, touch bool) (*models.Session, *models.User, error) {
	if token == "" {
		return nil, nil, models.ErrInvalidToken
	}
	sess, err := s.storage.SessionByTokenHash(ctx, crypto.HashToken(token))
	if errors.Is(err, models.ErrStorageNotFound) {
		return nil, nil, models.ErrInvalidToken
	}
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	if sess.Expired(now) {
		return nil, nil, models.ErrSessionExpired
	}
	last := sess.LastSeenAt
	if last.IsZero() {
		last = sess.CreatedAt
	}
	if s.policy.IdleTimeout > 0 && now.Sub(last) >= s.policy.IdleTimeout {
		return nil, nil, models.ErrSessionExpired
	}
	if sess.CredentialID != "" {
		if err := s.checkCredential(ctx, sess); err != nil {
			return nil, nil, err
		}
	}
	user, err := s.storage.UserByID(ctx, sess.UserID)
	if err != nil {
		return nil, nil, err
	}
	if touch && s.policy.Toucher != nil && s.policy.TouchInterval > 0 &&
		now.Sub(last) >= s.policy.TouchInterval && s.gate.allow(sess.ID, now, s.policy.TouchInterval) {
		if err := s.policy.Toucher.TouchSession(ctx, sess.ID, now); err != nil {
			slog.Warn("theauth: session last-seen update failed", "session_id", sess.ID.String(), "err", err.Error())
		} else {
			sess.LastSeenAt = now
		}
	}
	return sess, user, nil
}

// checkCredential fails closed: a session tied to a credential is unusable
// when no checker is configured or the checker cannot answer.
func (s *Service) checkCredential(ctx context.Context, sess *models.Session) error {
	if s.policy.Credentials == nil {
		return models.ErrSessionExpired
	}
	err := s.policy.Credentials.CheckCredential(ctx, sess.CredentialID)
	if err == nil {
		return nil
	}
	if !errors.Is(err, models.ErrCredentialRevoked) {
		return fmt.Errorf("theauth: check session credential: %w", err)
	}
	if s.policy.Revoker != nil {
		if rerr := s.policy.Revoker.RevokeSession(ctx, sess.ID); rerr != nil {
			slog.Warn("theauth: revoke session after credential revocation failed", "session_id", sess.ID.String(), "err", rerr.Error())
		}
	}
	return models.ErrSessionExpired
}
