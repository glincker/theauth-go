-- 0019: single use approval requests for guarded agent tool calls
-- (policy/toolguard). A request is pending until approved_at is set and spent
-- once consumed_at is set. Times are Unix microseconds, 0 meaning unset for
-- expires_at. No foreign keys: agent ids may belong to external registries.
CREATE TABLE IF NOT EXISTS theauth_tool_approvals (
    id          TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    requirement TEXT NOT NULL DEFAULT '',
    tier        TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT '',
    approver    TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL DEFAULT 0,
    approved_at INTEGER,
    consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS theauth_tool_approvals_expires_idx ON theauth_tool_approvals (expires_at);
