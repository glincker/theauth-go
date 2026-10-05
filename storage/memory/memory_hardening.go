package memory

import (
	"context"

	"github.com/glincker/theauth-go/v2"
)

var (
	_ theauth.TOTPReplayStorage = (*Store)(nil)
	_ theauth.UserCountStorage  = (*Store)(nil)
)

// AdvanceTOTPStep implements theauth.TOTPReplayStorage.
func (s *Store) AdvanceTOTPStep(_ context.Context, userID theauth.ULID, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.totpSteps[userID]; ok && step <= last {
		return false, nil
	}
	s.totpSteps[userID] = step
	return true, nil
}

// CountUsers implements theauth.UserCountStorage.
func (s *Store) CountUsers(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users), nil
}
