-- 0033: CIBA (RFC 9509) backchannel authentication requests, one row per
-- POST /oauth/bc-authorize call. status is one of pending, approved, denied,
-- consumed, expired. scope is a JSON array stored as TEXT. Times are Unix
-- microseconds; last_poll_at is NULL until the first poll. client_id has no
-- foreign key because the OAuth client table is owned by another migration
-- range and may be backed by an external registry.
CREATE TABLE IF NOT EXISTS theauth_backchannel_requests (
    auth_req_id               TEXT PRIMARY KEY,
    client_id                 TEXT NOT NULL,
    user_id                   TEXT REFERENCES theauth_users (id) ON DELETE SET NULL,
    login_hint                TEXT NOT NULL DEFAULT '',
    login_hint_token          TEXT NOT NULL DEFAULT '',
    id_token_hint             TEXT NOT NULL DEFAULT '',
    scope                     TEXT NOT NULL DEFAULT '[]',
    binding_message           TEXT NOT NULL DEFAULT '',
    client_notification_token TEXT NOT NULL DEFAULT '',
    status                    TEXT NOT NULL DEFAULT 'pending',
    access_token              TEXT NOT NULL DEFAULT '',
    refresh_token             TEXT NOT NULL DEFAULT '',
    id_token                  TEXT NOT NULL DEFAULT '',
    poll_interval             INTEGER NOT NULL DEFAULT 5,
    last_poll_at              INTEGER,
    expires_at                INTEGER NOT NULL,
    created_at                INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_backchannel_requests_client_idx ON theauth_backchannel_requests (client_id);
CREATE INDEX IF NOT EXISTS theauth_backchannel_requests_status_idx ON theauth_backchannel_requests (status);
CREATE INDEX IF NOT EXISTS theauth_backchannel_requests_expires_idx ON theauth_backchannel_requests (expires_at);
