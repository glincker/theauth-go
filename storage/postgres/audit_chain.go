package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/jackc/pgx/v5"
)

// ChainSupported reports that this backend keeps the tamper-evident audit hash chain.
func (s *Store) ChainSupported() bool { return true }

// auditSecret returns the installation secret, creating it on first use.
func auditSecret(ctx context.Context, tx pgx.Tx) ([]byte, error) {
	var secret []byte
	err := tx.QueryRow(ctx, `SELECT secret FROM theauth_audit_secrets WHERE id = 1`).Scan(&secret)
	if err == nil {
		return secret, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	fresh, err := audit.NewSecret()
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO theauth_audit_secrets (id, secret) VALUES (1, $1)
ON CONFLICT (id) DO NOTHING`, fresh); err != nil {
		return nil, err
	}
	// Re-read so a concurrent creator's value wins; under READ COMMITTED the insert blocks until commit.
	if err := tx.QueryRow(ctx, `SELECT secret FROM theauth_audit_secrets WHERE id = 1`).Scan(&secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// lockChainHeads locks each touched chain's head row (SELECT ... FOR UPDATE) until the batch
// commits, and returns the heads. A row lock rather than an advisory lock, so no key space is
// shared with the host app. Locks are taken in sorted key order to avoid deadlock.
//
// The second result is each chain's highest issued recorded_at_us, read under the same lock. The
// writer stamps rows above it, so stamps are strictly increasing per chain even across processes.
func lockChainHeads(ctx context.Context, tx pgx.Tx, events []theauth.AuditEvent) (map[string]audit.ChainHead, map[string]int64, error) {
	seen := map[string]struct{}{}
	for _, e := range events {
		seen[audit.ChainKey(e)] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	heads := make(map[string]audit.ChainHead, len(keys))
	stamps := make(map[string]int64, len(keys))
	for _, k := range keys {
		if _, err := tx.Exec(ctx, `INSERT INTO theauth_audit_chain_heads (chain_key, seq, hash)
VALUES ($1, 0, '') ON CONFLICT (chain_key) DO NOTHING`, k); err != nil {
			return nil, nil, err
		}
		var h audit.ChainHead
		var us int64
		if err := tx.QueryRow(ctx, `SELECT seq, hash, recorded_at_us FROM theauth_audit_chain_heads
WHERE chain_key = $1 FOR UPDATE`, k).Scan(&h.Seq, &h.Hash, &us); err != nil {
			return nil, nil, err
		}
		heads[k] = h
		stamps[k] = us
	}
	return heads, stamps, nil
}

// VerifyAuditChain walks every chain in seq order and reports the first mismatched row.
// Pre-0028 rows count as Unchained; erased rows verify via their pseudonyms and count as Erased.
func (s *Store) VerifyAuditChain(ctx context.Context) (theauth.AuditChainResult, error) {
	fail := func(err error) (theauth.AuditChainResult, error) {
		return theauth.AuditChainResult{Supported: true}, fmt.Errorf("postgres: verify audit chain: %w", err)
	}
	var unchained int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE chain_seq IS NULL`).Scan(&unchained); err != nil {
		return fail(err)
	}
	var secret []byte
	if err := s.pool.QueryRow(ctx, `SELECT secret FROM theauth_audit_secrets WHERE id = 1`).Scan(&secret); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fail(err)
	}
	rows, err := s.pool.Query(ctx, `
SELECT id, organization_id, actor_user_id, actor_session_id, action,
       COALESCE(target_type, ''), COALESCE(target_id, ''), chain_metadata, metadata,
       chain_ip, COALESCE(host(ip), ''), COALESCE(user_agent, ''), created_at,
       subject_id, actor_id, policy_version, approver_id, delegation_chain, input_provenance,
       actor_user_pseudonym, subject_pseudonym, actor_pseudonym, approver_pseudonym,
       chain_session, chain_key, chain_seq, prev_hash, hash
FROM audit_events WHERE chain_seq IS NOT NULL ORDER BY chain_key, chain_seq`)
	if err != nil {
		return fail(err)
	}
	defer rows.Close()
	res, err := audit.VerifyChainRows(func() (audit.ChainRow, bool, error) {
		if !rows.Next() {
			return audit.ChainRow{}, false, rows.Err()
		}
		r, err := scanChainRow(rows)
		return r, err == nil, err
	}, secret, unchained)
	if err != nil {
		return fail(err)
	}
	return res, nil
}
