package session

import (
	"context"
	"fmt"
	"sort"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// AccountGate vetoes issuing a session for a user, for example because the
// account is disabled or must change its password. It runs after the
// credential was verified, so its error may be specific.
type AccountGate interface {
	CheckSignin(ctx context.Context, userID models.ULID) error
}

// Overflow values for Cap.Mode.
const (
	// OverflowEvictOldest revokes the user's oldest sessions to make room.
	OverflowEvictOldest = "evict_oldest"
	// OverflowReject refuses the new session.
	OverflowReject = "reject"
)

// SessionLister lists a user's live sessions, newest first.
type SessionLister interface {
	ListUserSessions(ctx context.Context, userID models.ULID) ([]models.Session, error)
}

// Cap limits how many full sessions one user may hold at once. The zero value
// disables the cap. Enforcement is best effort under concurrency: two
// simultaneous sign-ins may both pass the check.
type Cap struct {
	Max     int
	Mode    string
	Lister  SessionLister
	Revoker Revoker
}

type noLimitKey struct{}

// WithoutLimits returns a context under which session issuance skips the
// concurrent session cap. It is for probe sessions that are revoked at once.
func WithoutLimits(ctx context.Context) context.Context {
	return context.WithValue(ctx, noLimitKey{}, true)
}

// SetAccountGate installs the gate consulted before every full session is
// issued. Call before the Service is shared.
func (s *Service) SetAccountGate(g AccountGate) { s.acct = g }

// SetCap installs the concurrent session cap. Call before the Service is shared.
func (s *Service) SetCap(c Cap) { s.cap = c }

// CheckAccount runs the account gate for userID. It returns nil when no gate is set.
func (s *Service) CheckAccount(ctx context.Context, userID models.ULID) error {
	if s.acct == nil {
		return nil
	}
	return s.acct.CheckSignin(ctx, userID)
}

// CapRoom returns CodeSessionLimit when the cap is in reject mode and userID
// is already at it, without revoking anything. Callers use it before spending
// a one-time credential (a recovery code) so a refusal does not burn it.
func (s *Service) CapRoom(ctx context.Context, userID, exclude models.ULID) error {
	if s.cap.Mode != OverflowReject {
		return nil
	}
	return s.EnforceCap(ctx, userID, exclude)
}

// EnforceCap makes room for one more full session of userID, ignoring the
// session exclude (use the zero ULID for none). With OverflowEvictOldest it
// revokes the oldest sessions; with OverflowReject it returns CodeSessionLimit.
func (s *Service) EnforceCap(ctx context.Context, userID, exclude models.ULID) error {
	if s.cap.Max <= 0 || s.cap.Lister == nil {
		return nil
	}
	if v, _ := ctx.Value(noLimitKey{}).(bool); v {
		return nil
	}
	rows, err := s.cap.Lister.ListUserSessions(ctx, userID)
	if err != nil {
		return fmt.Errorf("theauth: session cap: list sessions: %w", err)
	}
	live := make([]models.Session, 0, len(rows))
	for _, r := range rows {
		if r.ID != exclude && r.AuthLevel != models.AuthLevelPending2FA {
			live = append(live, r)
		}
	}
	over := len(live) - (s.cap.Max - 1)
	if over <= 0 {
		return nil
	}
	if s.cap.Mode == OverflowReject || s.cap.Revoker == nil {
		return models.NewError(models.CodeSessionLimit,
			fmt.Sprintf("at most %d concurrent sessions are allowed", s.cap.Max), nil)
	}
	sort.Slice(live, func(i, j int) bool { return live[i].CreatedAt.Before(live[j].CreatedAt) })
	for _, old := range live[:over] {
		if err := s.cap.Revoker.RevokeSession(ctx, old.ID); err != nil {
			return fmt.Errorf("theauth: session cap: evict session: %w", err)
		}
	}
	return nil
}
