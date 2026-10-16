-- 0017: audit accountability fields and tamper-evident hash chain.
-- Rows written before this migration keep chain_seq NULL and are reported as
-- unchained by the verifier; they are never rewritten.
ALTER TABLE theauth_audit_events ADD COLUMN subject_id TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_audit_events ADD COLUMN actor_id TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_audit_events ADD COLUMN policy_version TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_audit_events ADD COLUMN approver_id TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_audit_events ADD COLUMN delegation_chain TEXT NOT NULL DEFAULT '[]';
ALTER TABLE theauth_audit_events ADD COLUMN input_provenance TEXT NOT NULL DEFAULT '{}';
-- Keyed pseudonyms of the personal ids. The hash covers these instead of the raw
-- ids, so erasing a user (nulling actor_user_id etc.) leaves the chain intact.
ALTER TABLE theauth_audit_events ADD COLUMN actor_user_pseudonym TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_audit_events ADD COLUMN subject_pseudonym TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_audit_events ADD COLUMN actor_pseudonym TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_audit_events ADD COLUMN approver_pseudonym TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_audit_events ADD COLUMN chain_key TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_audit_events ADD COLUMN chain_seq INTEGER;
ALTER TABLE theauth_audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_audit_events ADD COLUMN hash TEXT NOT NULL DEFAULT '';

-- One chain per chain_key (the organization id, or '' for global events).
-- NULL chain_seq rows (legacy) never collide.
CREATE UNIQUE INDEX IF NOT EXISTS theauth_audit_chain_idx ON theauth_audit_events (chain_key, chain_seq);

-- Per-installation secret for the pseudonyms above. Created lazily by the first
-- chained write; there is only ever one row.
CREATE TABLE IF NOT EXISTS theauth_audit_secrets (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    secret     BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
