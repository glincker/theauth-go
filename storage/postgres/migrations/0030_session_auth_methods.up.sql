-- 0030: record how a session authenticated. auth_methods holds the RFC 8176
-- amr values proved so far (in order) and auth_time the last proof. Both are
-- NULL on sessions created before this migration, which readers treat as
-- "no record" and fall back to the old pwd default.
ALTER TABLE sessions
    ADD COLUMN auth_methods text[],
    ADD COLUMN auth_time    timestamptz;
