-- 0029: single use approval requests for guarded agent tool calls
-- (policy/toolguard). A request is pending until approved_at is set and spent
-- once consumed_at is set. expires_at NULL means the request never expires.
-- No foreign keys: agent ids may belong to external registries.
CREATE TABLE IF NOT EXISTS theauth_tool_approvals (
    id          text PRIMARY KEY,
    agent_id    text NOT NULL,
    action      text NOT NULL,
    resource    text NOT NULL,
    requirement text NOT NULL DEFAULT '',
    tier        text NOT NULL DEFAULT '',
    reason      text NOT NULL DEFAULT '',
    approver    text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz,
    approved_at timestamptz,
    consumed_at timestamptz
);

CREATE INDEX IF NOT EXISTS theauth_tool_approvals_expires_idx ON theauth_tool_approvals (expires_at);
