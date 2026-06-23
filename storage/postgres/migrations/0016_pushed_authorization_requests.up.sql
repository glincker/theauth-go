-- 0016: RFC 9126 Pushed Authorization Requests (PAR) storage table.
--
-- Each row holds one pushed request identified by its request_uri
-- (urn:ietf:params:oauth:request_uri:<256-bit-random>). The table uses
-- expires_at to encode the TTL; the application layer enforces expiry at
-- consume time but a periodic sweeper or background job may also purge
-- rows past expires_at.
--
-- consumed_at is set when the request is consumed by /oauth/authorize.
-- Rows that have never been consumed but whose expires_at is in the past
-- are equivalent to expired and MUST be treated identically.
--
-- The primary key is the request_uri string; no other lookup is needed.

CREATE TABLE IF NOT EXISTS pushed_authorization_requests (
    request_uri  TEXT        NOT NULL PRIMARY KEY,
    payload      BYTEA       NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ
);

-- Index for sweeping expired rows.
CREATE INDEX IF NOT EXISTS idx_par_expires_at ON pushed_authorization_requests (expires_at);
