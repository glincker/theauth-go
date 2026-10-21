-- Per period secrets for rotating audit pseudonyms. One row per period (whole days since
-- the epoch divided by the rotation length). Deleting a row shreds the period: pseudonyms
-- written under it can no longer be recomputed or linked. The chain hash covers the stored
-- pseudonyms, not these secrets, so shredding keeps the chain verifying. Separate from
-- theauth_audit_secrets, which holds the single installation secret.
CREATE TABLE IF NOT EXISTS theauth_audit_period_secrets (
    period     BIGINT NOT NULL PRIMARY KEY,
    secret     VARBINARY(64) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
);

-- A rotated pseudonym is tagged "r1:<period>:<64 hex>", up to about 90 characters, so the four
-- pseudonym columns widen from 64. Extending a VARCHAR inside the same length prefix class (these
-- are already over 255 bytes) is an in place change in InnoDB. Rows keep their values, and the
-- chain hash does not change.
ALTER TABLE audit_events
    MODIFY COLUMN actor_user_pseudonym VARCHAR(128) NOT NULL DEFAULT '',
    MODIFY COLUMN subject_pseudonym    VARCHAR(128) NOT NULL DEFAULT '',
    MODIFY COLUMN actor_pseudonym      VARCHAR(128) NOT NULL DEFAULT '',
    MODIFY COLUMN approver_pseudonym   VARCHAR(128) NOT NULL DEFAULT '';
