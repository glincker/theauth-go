-- 0028: audit accountability fields and tamper-evident hash chain.
-- Mirrors sqlite migration 0017. Rows written before this migration keep
-- chain_seq NULL and are reported as unchained by the verifier. They are never
-- rewritten, and their accountability fields (if any) stay under the reserved
-- _accountability metadata key.
ALTER TABLE audit_events
    ADD COLUMN subject_id            text NOT NULL DEFAULT '',
    ADD COLUMN actor_id              text NOT NULL DEFAULT '',
    ADD COLUMN policy_version        text NOT NULL DEFAULT '',
    ADD COLUMN approver_id           text NOT NULL DEFAULT '',
    ADD COLUMN delegation_chain      text NOT NULL DEFAULT '[]',
    ADD COLUMN input_provenance      text NOT NULL DEFAULT '{}',
    -- Keyed pseudonyms of the personal ids. The hash covers these instead of
    -- the raw ids, so erasing a user blanks the raw columns and keeps the chain.
    ADD COLUMN actor_user_pseudonym  text NOT NULL DEFAULT '',
    ADD COLUMN subject_pseudonym     text NOT NULL DEFAULT '',
    ADD COLUMN actor_pseudonym       text NOT NULL DEFAULT '',
    ADD COLUMN approver_pseudonym    text NOT NULL DEFAULT '',
    -- Exact text that was hashed. jsonb and inet normalise their values and the
    -- session foreign key is nulled when a session is deleted, so the hash is
    -- recomputed from these verbatim copies. The verifier also checks that the
    -- native columns still agree with them.
    ADD COLUMN chain_metadata        text NOT NULL DEFAULT '{}',
    ADD COLUMN chain_ip              text NOT NULL DEFAULT '',
    ADD COLUMN chain_session         text NOT NULL DEFAULT '',
    ADD COLUMN chain_key             text NOT NULL DEFAULT '',
    ADD COLUMN chain_seq             bigint,
    ADD COLUMN prev_hash             text NOT NULL DEFAULT '',
    ADD COLUMN hash                  text NOT NULL DEFAULT '';

-- One chain per chain_key (the organization id, or '' for global events).
-- Legacy rows have NULL chain_seq and never collide.
CREATE UNIQUE INDEX theauth_audit_chain_idx ON audit_events (chain_key, chain_seq)
    WHERE chain_seq IS NOT NULL;

-- Chain head per chain_key. Writers lock the head row (SELECT ... FOR UPDATE)
-- to serialize appends to one chain.
CREATE TABLE theauth_audit_chain_heads (
    chain_key text PRIMARY KEY,
    seq       bigint NOT NULL,
    hash      text NOT NULL
);

-- Per-installation secret for the pseudonyms above. Created lazily by the
-- first chained write. There is only ever one row.
CREATE TABLE theauth_audit_secrets (
    id         smallint PRIMARY KEY CHECK (id = 1),
    secret     bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
