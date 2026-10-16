-- 0034: record how a session authenticated. auth_methods is a JSON array of
-- the RFC 8176 amr values proved so far (in order) and auth_time the last
-- proof in unix microseconds. Both are NULL on sessions created before this
-- migration, which readers treat as "no record".
ALTER TABLE theauth_sessions ADD COLUMN auth_methods TEXT;
ALTER TABLE theauth_sessions ADD COLUMN auth_time INTEGER;
