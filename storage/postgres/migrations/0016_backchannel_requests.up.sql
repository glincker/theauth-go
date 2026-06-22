-- 0017: CIBA (RFC 9509) backchannel_requests table.
-- Stores one row per POST /oauth/bc-authorize call.
-- auth_req_id is a 256-bit base64url string, unique per AS instance.
-- status: pending | approved | denied
-- access_token, refresh_token are stored as plaintext JWT / opaque strings;
-- they are short-lived and only served once (on the first successful poll
-- after approval).

CREATE TABLE backchannel_requests (
    auth_req_id              TEXT        PRIMARY KEY,
    client_id                TEXT        NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id                  UUID        REFERENCES users(id) ON DELETE SET NULL,
    login_hint               TEXT        NOT NULL DEFAULT '',
    login_hint_token         TEXT        NOT NULL DEFAULT '',
    id_token_hint            TEXT        NOT NULL DEFAULT '',
    scope                    TEXT[]      NOT NULL DEFAULT '{}',
    binding_message          TEXT        NOT NULL DEFAULT '',
    client_notification_token TEXT       NOT NULL DEFAULT '',
    status                   TEXT        NOT NULL DEFAULT 'pending',
    access_token             TEXT        NOT NULL DEFAULT '',
    refresh_token            TEXT        NOT NULL DEFAULT '',
    id_token                 TEXT        NOT NULL DEFAULT '',
    poll_interval            INTEGER     NOT NULL DEFAULT 5,
    last_poll_at             TIMESTAMPTZ,
    expires_at               TIMESTAMPTZ NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_backchannel_requests_client_id ON backchannel_requests(client_id);
CREATE INDEX idx_backchannel_requests_status    ON backchannel_requests(status);
CREATE INDEX idx_backchannel_requests_expires_at ON backchannel_requests(expires_at);
