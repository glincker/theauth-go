-- 0015: Enforce at most one current JWKS signing key at the database level.
--
-- The partial unique index prevents a racing rotation call (or any direct
-- storage write) from leaving two rows with state = 'current'. The
-- IF NOT EXISTS guard makes this migration idempotent and safe to re-run.
--
-- Note: the index expression is a constant (true), so the index contains at
-- most one entry at any time. Attempting to set a second row to 'current'
-- while one already exists raises a unique-constraint violation, which
-- AtomicRotateJWKS surfaces as a transaction error and rolls back cleanly.
--
-- If your database already has two rows with state = 'current' the CREATE
-- INDEX will fail. Resolve the duplicate manually (set the stale row to
-- 'previous') before re-running migrations.

CREATE UNIQUE INDEX IF NOT EXISTS theauth_jwks_one_current
    ON jwks_keys ((state = 'current'))
    WHERE state = 'current';
