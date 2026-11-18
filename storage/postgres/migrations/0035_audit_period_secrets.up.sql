-- Per period secrets for rotating audit pseudonyms. One row per period (whole days since
-- the epoch divided by the rotation length). Deleting a row shreds the period: pseudonyms
-- written under it can no longer be recomputed or linked. The chain hash covers the stored
-- pseudonyms, not these secrets, so shredding keeps the chain verifying. Separate from
-- theauth_audit_secrets, which holds the single installation secret.
CREATE TABLE theauth_audit_period_secrets (
    period     bigint PRIMARY KEY,
    secret     bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
