package session

import (
	"context"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// AuthAppender is the storage capability Append needs; it is satisfied by
// theauth.SessionAuthStorage.
type AuthAppender interface {
	AppendSessionAuthMethods(ctx context.Context, id models.ULID, methods []string, at time.Time) ([]string, time.Time, error)
}

// Append atomically adds methods to the session's record and advances its
// AuthTime to at (now when zero). It returns the resulting record. When the
// storage lacks the capability it is a no-op returning nil, so third party
// storages keep working without a record.
func (s *Service) Append(ctx context.Context, id models.ULID, at time.Time, methods ...string) ([]string, time.Time, error) {
	ap, ok := s.storage.(AuthAppender)
	if !ok || len(methods) == 0 {
		return nil, time.Time{}, nil
	}
	if at.IsZero() {
		at = time.Now()
	}
	got, authTime, err := ap.AppendSessionAuthMethods(ctx, id, methods, at)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("session: append auth methods: %w", err)
	}
	return got, authTime, nil
}
