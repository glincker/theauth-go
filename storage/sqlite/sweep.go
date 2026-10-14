package sqlite

import (
	"context"
	"time"
)

// SweepResult counts rows removed by SweepExpired.
type SweepResult struct {
	Sessions            int64
	MagicLinks          int64
	PasswordResetTokens int64
	TrustedDevices      int64
	SessionLinks        int64
	DeviceCodes         int64
	DeviceJoinTokens    int64
}

// SweepExpired deletes expired rows whose expiry is at or before now: sessions, magic links, reset tokens,
// trusted devices, session links, device codes and device join tokens.
//
// Call it from a host ticker; consumed tokens are removed once they expire so
// replay detection is not weakened early. Tables from migrations the host has
// not applied yet are skipped.
func (s *Store) SweepExpired(ctx context.Context, now time.Time) (SweepResult, error) {
	var res SweepResult
	cutoff := toMicro(now)
	err := s.inTx(ctx, "sweep expired", func(tx DBTX) error {
		targets := []struct {
			table string
			out   *int64
		}{
			{"theauth_sessions", &res.Sessions},
			{"theauth_magic_links", &res.MagicLinks},
			{"theauth_password_reset_tokens", &res.PasswordResetTokens},
			{"theauth_trusted_devices", &res.TrustedDevices},
			{"theauth_session_links", &res.SessionLinks},
			{"theauth_device_codes", &res.DeviceCodes},
			{"theauth_device_join_tokens", &res.DeviceJoinTokens},
		}
		for _, t := range targets {
			r, err := tx.ExecContext(ctx, s.q(`DELETE FROM `+t.table+` WHERE expires_at <= ?`), cutoff)
			if err != nil {
				if isMissingTable(err) {
					continue
				}
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
