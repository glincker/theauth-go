package mysql

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
	mysqldrv "github.com/go-sql-driver/mysql"
)

// AuditProvenanceSupported declares that AuditQuery.Provenance is served.
func (s *Store) AuditProvenanceSupported() bool { return true }

// SetAuditPseudonymRotation turns on rotating audit pseudonyms (theauth.AuditPseudonymRotator).
// It needs migration 0033. Rows written before keep their stable pseudonym and still verify.
func (s *Store) SetAuditPseudonymRotation(r audit.Rotation) error { return s.rot.Set(&r) }

// ShredAuditPseudonyms deletes the period secrets outside the retention window and returns the
// periods removed (theauth.AuditPseudonymRotator).
func (s *Store) ShredAuditPseudonyms(ctx context.Context) ([]int64, error) {
	rot := s.rot.Get()
	if rot == nil {
		return nil, nil
	}
	return audit.ShredStalePeriods(ctx, myPeriods{s.db}, audit.PeriodOf(time.Now(), rot.PeriodDays), rot.RetainPeriods)
}

// myPeriods is the period secret table, used in autocommit statements.
type myPeriods struct{ db *sql.DB }

func (p myPeriods) read(ctx context.Context, period int64) ([]byte, error) {
	var secret []byte
	err := p.db.QueryRowContext(ctx, `SELECT secret FROM theauth_audit_period_secrets WHERE period = ?`, period).Scan(&secret)
	return secret, err
}

func (p myPeriods) GetOrCreate(ctx context.Context, period int64) ([]byte, error) {
	secret, err := p.read(ctx, period)
	if err == nil {
		return secret, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	fresh, err := audit.NewPeriodSecret()
	if err != nil {
		return nil, err
	}
	if _, err := p.db.ExecContext(ctx, `INSERT IGNORE INTO theauth_audit_period_secrets (period, secret) VALUES (?, ?)`, period, fresh); err != nil {
		return nil, err
	}
	// Re-read so a concurrent creator's value wins.
	return p.read(ctx, period)
}

func (p myPeriods) Periods(ctx context.Context) ([]int64, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT period FROM theauth_audit_period_secrets`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
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

func (p myPeriods) Delete(ctx context.Context, periods []int64) error {
	for _, n := range periods {
		if _, err := p.db.ExecContext(ctx, `DELETE FROM theauth_audit_period_secrets WHERE period = ?`, n); err != nil {
			return err
		}
	}
	return nil
}

// periodSecrets reads every period secret for verification. A database not yet migrated to 0033
// has no rotated rows.
func (s *Store) periodSecrets(ctx context.Context) (map[int64][]byte, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT period, secret FROM theauth_audit_period_secrets`)
	if err != nil {
		var me *mysqldrv.MySQLError
		if errors.As(err, &me) && me.Number == 1146 {
			return map[int64][]byte{}, nil
		}
		return nil, err
	}
	defer func() { _ = rows.Close() }()
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
