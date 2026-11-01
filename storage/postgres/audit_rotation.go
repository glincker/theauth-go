package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// AuditProvenanceSupported declares that AuditQuery.Provenance is served.
func (s *Store) AuditProvenanceSupported() bool { return true }

// SetAuditPseudonymRotation turns on rotating audit pseudonyms (theauth.AuditPseudonymRotator).
// It needs migration 0035. Rows written before keep their stable pseudonym and still verify.
func (s *Store) SetAuditPseudonymRotation(r audit.Rotation) error { return s.rot.Set(&r) }

// ShredAuditPseudonyms deletes the period secrets outside the retention window and returns the
// periods removed (theauth.AuditPseudonymRotator).
func (s *Store) ShredAuditPseudonyms(ctx context.Context) ([]int64, error) {
	rot := s.rot.Get()
	if rot == nil {
		return nil, nil
	}
	return audit.ShredStalePeriods(ctx, pgPeriods{s.pool}, audit.PeriodOf(time.Now(), rot.PeriodDays), rot.RetainPeriods)
}

// pgQuerier is satisfied by pgx.Tx and *pgxpool.Pool.
type pgQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// pgPeriods is the period secret table, read and written on the batch transaction on the write
// path, so a rolled back batch leaves no secret behind.
type pgPeriods struct{ q pgQuerier }

func (p pgPeriods) read(ctx context.Context, period int64) ([]byte, error) {
	var secret []byte
	err := p.q.QueryRow(ctx, `SELECT secret FROM theauth_audit_period_secrets WHERE period = $1`, period).Scan(&secret)
	return secret, err
}

func (p pgPeriods) GetOrCreate(ctx context.Context, period int64) ([]byte, error) {
	secret, err := p.read(ctx, period)
	if err == nil {
		return secret, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	fresh, err := audit.NewPeriodSecret()
	if err != nil {
		return nil, err
	}
	if _, err := p.q.Exec(ctx, `INSERT INTO theauth_audit_period_secrets (period, secret) VALUES ($1, $2)
ON CONFLICT (period) DO NOTHING`, period, fresh); err != nil {
		return nil, err
	}
	// Re-read so a concurrent creator's value wins; under READ COMMITTED the insert blocks until commit.
	return p.read(ctx, period)
}

func (p pgPeriods) Periods(ctx context.Context) ([]int64, error) {
	rows, err := p.q.Query(ctx, `SELECT period FROM theauth_audit_period_secrets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var n int64
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (p pgPeriods) Delete(ctx context.Context, periods []int64) error {
	_, err := p.q.Exec(ctx, `DELETE FROM theauth_audit_period_secrets WHERE period = ANY($1)`, periods)
	return err
}

// periodSecrets reads every period secret for verification.
func (s *Store) periodSecrets(ctx context.Context) (map[int64][]byte, error) {
	rows, err := s.pool.Query(ctx, `SELECT period, secret FROM theauth_audit_period_secrets`)
	if err != nil {
		// A database not yet migrated to 0035 has no rotated rows.
		if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			return map[int64][]byte{}, nil
		}
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]byte{}
	for rows.Next() {
		var (
			n      int64
			secret []byte
		)
		if err := rows.Scan(&n, &secret); err != nil {
			return nil, err
		}
		out[n] = secret
	}
	return out, rows.Err()
}
