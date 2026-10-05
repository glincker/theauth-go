package sqlite

import (
	"context"

	"github.com/glincker/theauth-go"
)

var (
	_ theauth.TOTPReplayStorage = (*Store)(nil)
	_ theauth.UserCountStorage  = (*Store)(nil)
)

// AdvanceTOTPStep records step as the user's last used TOTP step, returning false when it is not strictly newer.
func (s *Store) AdvanceTOTPStep(ctx context.Context, userID theauth.ULID, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_totp_last_steps (user_id, step) VALUES (?, ?)
ON CONFLICT (user_id) DO UPDATE SET step = excluded.step WHERE excluded.step > theauth_totp_last_steps.step`),
		idStr(userID), step)
	if err != nil {
		return false, wrap("advance totp step", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, wrap("advance totp step", err)
	}
	return n == 1, nil
}

// CountUsers returns the number of user rows.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM theauth_users`)).Scan(&n); err != nil {
		return 0, wrap("count users", err)
	}
	return n, nil
}
