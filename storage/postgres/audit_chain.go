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

// ChainSupported reports that this backend keeps a tamper-evident audit hash
// chain, hashed identically to storage/sqlite (see audit.ChainPayload).
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
	// Re-read so a concurrent creator's value wins consistently. Under READ
	// COMMITTED the conflicting insert blocks until the other writer commits.
	if err := tx.QueryRow(ctx, `SELECT secret FROM theauth_audit_secrets WHERE id = 1`).Scan(&secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// lockChainHeads locks the chain head row of every chain the batch touches and
// returns the current heads.
//
// Concurrency choice: a row lock (SELECT ... FOR UPDATE) on a per-chain head
// row in theauth_audit_chain_heads, held until the batch transaction commits.
// Writers to the same chain queue behind it, writers to different chains do
// not block each other, and no advisory-lock key space is shared with the
// host application. Locks are taken in sorted key order so two batches that
// touch several chains cannot deadlock. The head row is created on demand with
// ON CONFLICT DO NOTHING before it is locked.
func lockChainHeads(ctx context.Context, tx pgx.Tx, events []theauth.AuditEvent) (map[string]audit.ChainHead, error) {
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
	for _, k := range keys {
		if _, err := tx.Exec(ctx, `INSERT INTO theauth_audit_chain_heads (chain_key, seq, hash)
VALUES ($1, 0, '') ON CONFLICT (chain_key) DO NOTHING`, k); err != nil {
			return nil, err
		}
		var h audit.ChainHead
		if err := tx.QueryRow(ctx, `SELECT seq, hash FROM theauth_audit_chain_heads
WHERE chain_key = $1 FOR UPDATE`, k).Scan(&h.Seq, &h.Hash); err != nil {
			return nil, err
		}
		heads[k] = h
	}
	return heads, nil
}

// VerifyAuditChain walks every chain in seq order and reports the first row
// whose link or hash does not match. Rows written before migration 0028 have
// no chain position and are counted as Unchained, not as failures. Rows whose
// raw ids were erased still verify through the stored pseudonyms and are
// counted in Erased. Where a raw id is still present it must match its
// pseudonym, so editing a raw column is reported as pseudonym_mismatch.
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
