-- 0012: OpenID Shared Signals Framework transmitter state. A stream is one
-- receiver subscription (the full document is kept as JSON), subjects are
-- the optional per-stream subject filter, and the queue holds signed SETs
-- awaiting push delivery or poll acknowledgement. No foreign keys: rows are
-- removed explicitly when a stream is deleted.
CREATE TABLE IF NOT EXISTS theauth_signal_streams (
    id          TEXT PRIMARY KEY,
    receiver_id TEXT NOT NULL,
    doc         TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_signal_streams_receiver_idx ON theauth_signal_streams (receiver_id, created_at);

CREATE TABLE IF NOT EXISTS theauth_signal_subjects (
    stream_id   TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    subject     TEXT NOT NULL,
    PRIMARY KEY (stream_id, subject_key)
);

CREATE TABLE IF NOT EXISTS theauth_signal_queue (
    id         TEXT PRIMARY KEY,
    stream_id  TEXT NOT NULL,
    jti        TEXT NOT NULL,
    token      TEXT NOT NULL,
    push       INTEGER NOT NULL DEFAULT 0,
    attempts   INTEGER NOT NULL DEFAULT 0,
    next_at    INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_signal_queue_stream_idx ON theauth_signal_queue (stream_id, created_at);
CREATE INDEX IF NOT EXISTS theauth_signal_queue_due_idx ON theauth_signal_queue (push, next_at);
