package sqlite

import (
	"context"
	"database/sql"
	"time"
)

// SweepResult counts rows removed by SweepExpired.
type SweepResult struct {
	Sessions            int64
	MagicLinks          int64
	PasswordResetTokens int64
}

// SweepExpired deletes sessions, magic links and reset tokens whose expiry is at or before now.
//
// Call it from a host ticker; consumed tokens are removed once they expire so
// replay detection is not weakened early.
func (s *Store) SweepExpired(ctx context.Context, now time.Time) (SweepResult, error) {
	var res SweepResult
	cutoff := toMicro(now)
	err := s.inTx(ctx, "sweep expired", func(tx *sql.Tx) error {
		targets := []struct {
			table string
			out   *int64
		}{
			{"theauth_sessions", &res.Sessions},
			{"theauth_magic_links", &res.MagicLinks},
			{"theauth_password_reset_tokens", &res.PasswordResetTokens},
		}
		for _, t := range targets {
			r, err := tx.ExecContext(ctx, s.q(`DELETE FROM `+t.table+` WHERE expires_at <= ?`), cutoff)
			if err != nil {
				return err
			}
			if *t.out, err = r.RowsAffected(); err != nil {
				return err
			}
		}
		return nil
	})
	return res, err
}
