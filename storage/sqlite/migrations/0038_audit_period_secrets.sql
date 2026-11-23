-- 0038: per period secrets for rotating audit pseudonyms. One row per period (whole days
-- since the epoch divided by the rotation length). Deleting a row shreds the period: the
-- pseudonyms written under it can no longer be recomputed or linked. The chain hash covers
-- the stored pseudonyms, not these secrets, so shredding keeps the chain verifying.
-- Separate from theauth_audit_secrets, which holds the single installation secret.
CREATE TABLE IF NOT EXISTS theauth_audit_period_secrets (
    period     INTEGER PRIMARY KEY,
    secret     BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
