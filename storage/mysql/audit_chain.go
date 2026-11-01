package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/audit"
	mysqldrv "github.com/go-sql-driver/mysql"
)

// ChainSupported reports that this backend keeps a tamper-evident audit hash
// chain, hashed identically to storage/sqlite (see audit.ChainPayload).
func (s *Store) ChainSupported() bool { return true }

const insertChainedAuditSQL = `
INSERT INTO audit_events
    (id, organization_id, actor_user_id, actor_session_id, action, target_type, target_id,
     metadata, ip, user_agent, created_at,
     subject_id, actor_id, policy_version, approver_id, delegation_chain, input_provenance,
     actor_user_pseudonym, subject_pseudonym, actor_pseudonym, approver_pseudonym,
     chain_metadata, chain_session, chain_key, chain_seq, prev_hash, hash,
     event, recorded_at_us)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// maxDeadlockRetries bounds replays of a batch picked as InnoDB deadlock victim (1213).
// Head locks are taken in sorted order, so this is a safety net only.
const maxDeadlockRetries = 5

func isDeadlock(err error) bool {
	var me *mysqldrv.MySQLError
	return errors.As(err, &me) && me.Number == 1213
}

// InsertAuditEvents appends a batch in one transaction. Concurrent writers serialize per
// chain on a row lock on its head (see lockChainHeads).
func (s *Store) InsertAuditEvents(ctx context.Context, events []theauth.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	return retryDeadlock(ctx, func() error { return s.insertChained(ctx, events) })
}

// deadlockBackoffBase is the first retry delay; it doubles per attempt.
var deadlockBackoffBase = 10 * time.Millisecond

// retryDeadlock runs fn with bounded exponential backoff on InnoDB deadlock victims.
func retryDeadlock(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt <= maxDeadlockRetries; attempt++ {
		if cerr := ctx.Err(); cerr != nil {
			if err != nil {
				return fmt.Errorf("mysql: audit insert retry aborted: %w (last error: %v)", cerr, err)
			}
			return cerr
		}
		if err = fn(); !isDeadlock(err) {
			return err
		}
		if attempt == maxDeadlockRetries {
			break
		}
		t := time.NewTimer(deadlockBackoffBase << attempt)
		select {
		case <-ctx.Done():
			t.Stop()
			return fmt.Errorf("mysql: audit insert retry aborted: %w (last error: %v)", ctx.Err(), err)
		case <-t.C:
		}
	}
	return err
}

func (s *Store) insertChained(ctx context.Context, events []theauth.AuditEvent) error {
	if err := s.ensureChainRows(ctx, events); err != nil {
		return err
	}
	// Period secrets are created in autocommit statements before the batch transaction, like the
	// chain heads, so two first writers of a period cannot deadlock inside it. The stable secret
	// is read inside the transaction and added below.
	times := make([]time.Time, len(events))
	for i, e := range events {
		times[i] = e.CreatedAt
		if times[i].IsZero() {
			times[i] = time.Now()
		}
	}
	ps, err := s.rot.Resolve(ctx, nil, myPeriods{s.db}, times)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	secret, err := auditSecret(ctx, tx)
	if err != nil {
		return err
	}
	ps.Stable = secret
	heads, recorded, err := lockChainHeads(ctx, tx, events)
	if err != nil {
		return err
	}
	for i, e := range events {
		e.CreatedAt = times[i]
		key := audit.ChainKey(e)
		entry, err := audit.BuildChainEntryWith(e, ps, heads[key])
		if err != nil {
			return err
		}
		// The write order stamp is assigned here, while this transaction holds the head row
		// lock for the chain. The floor is the highest stamp the chain issued, so stamps are
		// strictly increasing per chain even across processes and a stalled clock. Any value
		// the caller set is ignored. Never hashed.
		recordedUs := audit.NextRecordedAtUs(recorded[key])
		var ipVal any
		if e.IP != "" {
			ipVal = e.IP
		}
		p := entry.Payload
		if _, err := tx.ExecContext(ctx, insertChainedAuditSQL,
			ulidToBytes(e.ID), ulidPtrToBytes(e.OrganizationID), ulidPtrToBytes(e.ActorUserID),
			ulidPtrToBytes(e.ActorSessionID), e.Action, nullStringVal(e.TargetType), nullStringVal(e.TargetID),
			entry.Metadata, ipVal, nullStringVal(e.UserAgent),
			timeUTC(time.UnixMicro(entry.CreatedAtMicro)),
			e.SubjectID, e.ActorID, e.PolicyVersion, e.ApproverID, entry.DelegationChain, entry.InputProvenance,
			p.ActorUserPseudo, p.SubjectPseudo, p.ActorPseudo, p.ApproverPseudo,
			entry.Metadata, p.ActorSession, key, p.Seq, p.Prev, entry.Hash,
			nullStringVal(e.Event), recordedUs); err != nil {
			return err
		}
		heads[key] = audit.ChainHead{Seq: p.Seq, Hash: entry.Hash}
		recorded[key] = recordedUs
	}
	for k, h := range heads {
		if _, err := tx.ExecContext(ctx, `UPDATE theauth_audit_chain_heads SET seq = ?, hash = ?, recorded_at_us = ? WHERE chain_key = ?`,
			h.Seq, h.Hash, recorded[k], k); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ensureChainRows creates the installation secret and missing chain heads in autocommit
// statements before the batch transaction. Inside it, two first writers would deadlock
// upgrading shared locks to FOR UPDATE.
func (s *Store) ensureChainRows(ctx context.Context, events []theauth.AuditEvent) error {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM theauth_audit_secrets WHERE id = 1`).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		fresh, gerr := audit.NewSecret()
		if gerr != nil {
			return gerr
		}
		_, err = s.db.ExecContext(ctx, `INSERT IGNORE INTO theauth_audit_secrets (id, secret) VALUES (1, ?)`, fresh)
	}
	if err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, e := range events {
		k := audit.ChainKey(e)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		if _, err := s.db.ExecContext(ctx, `INSERT IGNORE INTO theauth_audit_chain_heads (chain_key, seq, hash)
VALUES (?, 0, '')`, k); err != nil {
			return err
		}
	}
	return nil
}

// auditSecret returns the installation secret (created by ensureChainRows).
func auditSecret(ctx context.Context, tx *sql.Tx) ([]byte, error) {
	var secret []byte
	if err := tx.QueryRowContext(ctx, `SELECT secret FROM theauth_audit_secrets WHERE id = 1`).Scan(&secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// lockChainHeads locks the head row of every chain the batch touches and returns the heads
// plus the highest write order stamp each chain has issued.
// A row lock, not GET_LOCK (session scoped, leaks across pooled connections), taken in
// sorted key order. Head rows already exist, so no gap locks are involved.
func lockChainHeads(ctx context.Context, tx *sql.Tx, events []theauth.AuditEvent) (map[string]audit.ChainHead, map[string]int64, error) {
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
	recorded := make(map[string]int64, len(keys))
	for _, k := range keys {
		var (
			h  audit.ChainHead
			us int64
		)
		if err := tx.QueryRowContext(ctx, `SELECT seq, hash, recorded_at_us FROM theauth_audit_chain_heads
WHERE chain_key = ? FOR UPDATE`, k).Scan(&h.Seq, &h.Hash, &us); err != nil {
			return nil, nil, err
		}
		heads[k] = h
		recorded[k] = us
	}
	return heads, recorded, nil
}

// VerifyAuditChain walks every chain in seq order and reports the first mismatched row.
// Pre-0027 rows count as Unchained; erased rows verify via their pseudonyms and count as Erased.
func (s *Store) VerifyAuditChain(ctx context.Context) (theauth.AuditChainResult, error) {
	fail := func(err error) (theauth.AuditChainResult, error) {
		return theauth.AuditChainResult{Supported: true}, fmt.Errorf("mysql: verify audit chain: %w", err)
	}
	var unchained int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE chain_seq IS NULL`).Scan(&unchained); err != nil {
		return fail(err)
	}
	var secret []byte
	if err := s.db.QueryRowContext(ctx, `SELECT secret FROM theauth_audit_secrets WHERE id = 1`).Scan(&secret); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fail(err)
	}
	periods, err := s.periodSecrets(ctx)
	if err != nil {
		return fail(err)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, organization_id, actor_user_id, actor_session_id, action,
       COALESCE(target_type, ''), COALESCE(target_id, ''), chain_metadata, metadata,
       COALESCE(ip, ''), COALESCE(user_agent, ''), created_at,
       subject_id, actor_id, policy_version, approver_id,
       COALESCE(delegation_chain, '[]'), COALESCE(input_provenance, '{}'),
       actor_user_pseudonym, subject_pseudonym, actor_pseudonym, approver_pseudonym,
       chain_session, chain_key, chain_seq, prev_hash, hash
FROM audit_events WHERE chain_seq IS NOT NULL ORDER BY chain_key, chain_seq`)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = rows.Close() }()
	res, err := audit.VerifyChainRowsKeys(func() (audit.ChainRow, bool, error) {
		if !rows.Next() {
			return audit.ChainRow{}, false, rows.Err()
		}
		r, err := scanChainRow(rows)
		return r, err == nil, err
	}, audit.PseudonymKeys{Stable: secret, Periods: periods}, unchained)
	if err != nil {
		return fail(err)
	}
	return res, nil
}

// scanChainRow reads one chained row (column order fixed by VerifyAuditChain).
func scanChainRow(rows *sql.Rows) (audit.ChainRow, error) {
	var (
		r                             audit.ChainRow
		p                             = &r.Payload
		id, org, actorUser, actorSess []byte
		chainMeta                     sql.NullString
		metaNative                    []byte
		created                       time.Time
	)
	if err := rows.Scan(&id, &org, &actorUser, &actorSess, &p.Action,
		&p.TargetType, &p.TargetID, &chainMeta, &metaNative,
		&p.IP, &p.UserAgent, &created,
		&r.RawSubject, &r.RawActor, &p.PolicyVersion, &r.RawApprover, &p.DelegationChain, &p.InputProvenance,
		&p.ActorUserPseudo, &p.SubjectPseudo, &p.ActorPseudo, &p.ApproverPseudo,
		&p.ActorSession, &p.ChainKey, &p.Seq, &p.Prev, &r.Hash); err != nil {
		return r, err
	}
	p.Metadata = chainMeta.String
	p.ID = bytesToULID(id).String()
	p.Org = p.ChainKey
	p.CreatedAt = created.UTC().UnixMicro()
	if len(org) > 0 {
		r.RawOrg = bytesToULID(org).String()
	}
	if len(actorUser) > 0 {
		r.RawActorUser = bytesToULID(actorUser).String()
	}
	if len(actorSess) > 0 {
		r.RawSession = bytesToULID(actorSess).String()
	}
	if !jsonEqual(p.Metadata, metaNative) {
		r.ExtraBreak = "hash_mismatch"
	}
	return r, nil
}

// jsonEqual compares hashed text and the JSON column as JSON values, since MySQL's JSON
// type reorders keys.
func jsonEqual(text string, native []byte) bool {
	var a, b any
	if json.Unmarshal([]byte(text), &a) != nil || json.Unmarshal(native, &b) != nil {
		return false
	}
	return reflect.DeepEqual(a, b)
}
