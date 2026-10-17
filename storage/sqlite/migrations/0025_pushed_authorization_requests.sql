-- 0025: RFC 9126 pushed authorization requests. One row per request_uri. The
-- consume step is a conditional UPDATE on consumed_at IS NULL and expiry, so a
-- request is redeemed at most once.
CREATE TABLE IF NOT EXISTS theauth_pushed_authorization_requests (
    request_uri TEXT PRIMARY KEY,
    payload     BLOB NOT NULL,
    expires_at  INTEGER NOT NULL,
    consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS theauth_pushed_authorization_requests_expires_idx ON theauth_pushed_authorization_requests (expires_at);
