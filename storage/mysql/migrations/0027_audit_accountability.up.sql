-- 0027: audit accountability fields and tamper-evident hash chain.
-- Mirrors sqlite migration 0017. Rows written before this migration keep
-- chain_seq NULL and are reported as unchained by the verifier. They are never
-- rewritten, and their accountability fields (if any) stay under the reserved
-- _accountability metadata key.
-- The LONGTEXT columns are nullable on purpose: MySQL TEXT types cannot carry
-- a literal default, and every chained insert supplies them.
-- chain_metadata and chain_session hold the exact text that was hashed. The
-- JSON column reorders keys and the session foreign key is nulled when a
-- session is deleted, so the hash is recomputed from these verbatim copies.
ALTER TABLE audit_events
    ADD COLUMN subject_id            VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN actor_id              VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN policy_version        VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN approver_id           VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN delegation_chain      LONGTEXT NULL,
    ADD COLUMN input_provenance      LONGTEXT NULL,
    ADD COLUMN actor_user_pseudonym  VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN subject_pseudonym     VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN actor_pseudonym       VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN approver_pseudonym    VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN chain_metadata        LONGTEXT NULL,
    ADD COLUMN chain_session         VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN chain_key             VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN chain_seq             BIGINT NULL,
    ADD COLUMN prev_hash             VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN hash                  VARCHAR(64) NOT NULL DEFAULT '';

-- One chain per chain_key (the organization id, or empty for global events).
-- Legacy rows have NULL chain_seq and never collide.
CREATE UNIQUE INDEX theauth_audit_chain_idx ON audit_events (chain_key, chain_seq);

-- Chain head per chain_key. Writers lock the head row (SELECT ... FOR UPDATE)
-- to serialize appends to one chain.
CREATE TABLE IF NOT EXISTS theauth_audit_chain_heads (
    chain_key VARCHAR(64) NOT NULL PRIMARY KEY,
    seq       BIGINT NOT NULL,
    hash      VARCHAR(64) NOT NULL
);

-- Per-installation secret for the pseudonyms above. Created lazily by the
-- first chained write. There is only ever one row.
CREATE TABLE IF NOT EXISTS theauth_audit_secrets (
    id         TINYINT NOT NULL PRIMARY KEY,
    secret     VARBINARY(64) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT theauth_audit_secrets_one CHECK (id = 1)
);
