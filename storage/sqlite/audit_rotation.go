package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/audit"
)

// AuditProvenanceSupported declares that AuditQuery.Provenance is served.
func (s *Store) AuditProvenanceSupported() bool { return true }

// SetAuditPseudonymRotation turns on rotating audit pseudonyms (theauth.AuditPseudonymRotator).
// It needs migration 0038. Rows written before keep their stable pseudonym and still verify.
func (s *Store) SetAuditPseudonymRotation(r audit.Rotation) error { return s.rot.Set(&r) }

// ShredAuditPseudonyms deletes the period secrets outside the retention window and returns the
// periods removed (theauth.AuditPseudonymRotator).
func (s *Store) ShredAuditPseudonyms(ctx context.Context) ([]int64, error) {
	rot := s.rot.Get()
	if rot == nil {
		return nil, nil
	}
	return audit.ShredStalePeriods(ctx, periodStore{s, s.db}, audit.PeriodOf(time.Now(), rot.PeriodDays), rot.RetainPeriods)
}

// periodStore is the period secret table, read and written on q (the batch transaction on the
// write path, so a rolled back batch leaves no secret behind).
type periodStore struct {
	s *Store
	q DBTX
}

func (p periodStore) read(ctx context.Context, period int64) ([]byte, error) {
	var secret []byte
	err := p.q.QueryRowContext(ctx, p.s.q(`SELECT secret FROM theauth_audit_period_secrets WHERE period = ?`), period).Scan(&secret)
	return secret, err
}

func (p periodStore) GetOrCreate(ctx context.Context, period int64) ([]byte, error) {
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
	if _, err := p.q.ExecContext(ctx, p.s.q(
		`INSERT INTO theauth_audit_period_secrets (period, secret, created_at) VALUES (?, ?, ?)
ON CONFLICT (period) DO NOTHING`), period, fresh, toMicro(time.Now())); err != nil {
		return nil, err
	}
	// Re-read so a concurrent creator's value wins.
	return p.read(ctx, period)
}

func (p periodStore) Periods(ctx context.Context) ([]int64, error) {
	rows, err := p.q.QueryContext(ctx, p.s.q(`SELECT period FROM theauth_audit_period_secrets`))
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

func (p periodStore) Delete(ctx context.Context, periods []int64) error {
	for _, n := range periods {
		if _, err := p.q.ExecContext(ctx, p.s.q(`DELETE FROM theauth_audit_period_secrets WHERE period = ?`), n); err != nil {
			return err
		}
	}
	return nil
}

// auditPseudonymKeys reads the stable secret and every period secret for verification. A database
// migrated only to 0037 has no period table, which just means no rotated rows.
func (s *Store) auditPseudonymKeys(ctx context.Context) (audit.PseudonymKeys, error) {
	stable, err := s.auditSecretIfPresent(ctx)
	if err != nil {
		return audit.PseudonymKeys{}, err
	}
	keys := audit.PseudonymKeys{Stable: stable, Periods: map[int64][]byte{}}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT period, secret FROM theauth_audit_period_secrets`))
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return keys, nil
		}
		return keys, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			n      int64
			secret []byte
		)
		if err := rows.Scan(&n, &secret); err != nil {
			return keys, err
		}
		keys.Periods[n] = secret
	}
	return keys, rows.Err()
}
