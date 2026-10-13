-- 0026: OpenID Shared Signals Framework transmitter state. A stream is one
-- receiver subscription (the full document is kept as JSON), subjects are
-- the optional per-stream subject filter, and the queue holds signed SETs
-- awaiting push delivery or poll acknowledgement. No foreign keys: rows are
-- removed explicitly when a stream is deleted.
CREATE TABLE IF NOT EXISTS signal_streams (
    id          text PRIMARY KEY,
    receiver_id text NOT NULL,
    doc         text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_signal_streams_receiver ON signal_streams (receiver_id, created_at);

CREATE TABLE IF NOT EXISTS signal_subjects (
    stream_id   text NOT NULL,
    subject_key text NOT NULL,
    subject     text NOT NULL,
    PRIMARY KEY (stream_id, subject_key)
);

CREATE TABLE IF NOT EXISTS signal_queue (
    id         text PRIMARY KEY,
    stream_id  text NOT NULL,
    jti        text NOT NULL,
    token      text NOT NULL,
    push       boolean NOT NULL DEFAULT false,
    attempts   integer NOT NULL DEFAULT 0,
    next_at    timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_signal_queue_stream ON signal_queue (stream_id, created_at);
CREATE INDEX IF NOT EXISTS idx_signal_queue_due ON signal_queue (push, next_at);
