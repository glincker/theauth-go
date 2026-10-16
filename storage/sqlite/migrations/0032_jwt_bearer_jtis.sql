-- 0032: durable JTI replay cache for RFC 7523 client assertions and bearer
-- grant assertions (theauth.JWTBearerStorage). expires_at is Unix microseconds.
CREATE TABLE IF NOT EXISTS theauth_jwt_bearer_jtis (
    jti        TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_theauth_jwt_bearer_jtis_expires ON theauth_jwt_bearer_jtis (expires_at);
