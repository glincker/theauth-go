-- 0028: single use approval requests for guarded agent tool calls
-- (policy/toolguard). A request is pending until approved_at is set and spent
-- once consumed_at is set. expires_at NULL means the request never expires.
-- No foreign keys: agent ids may belong to external registries. Text columns
-- are VARCHAR so they stay inside the utf8mb4 index and row limits.
CREATE TABLE IF NOT EXISTS theauth_tool_approvals (
    id          VARCHAR(64) NOT NULL PRIMARY KEY,
    agent_id    VARCHAR(255) NOT NULL,
    action      VARCHAR(255) NOT NULL,
    resource    VARCHAR(512) NOT NULL,
    requirement VARCHAR(64) NOT NULL DEFAULT '',
    tier        VARCHAR(64) NOT NULL DEFAULT '',
    reason      VARCHAR(1024) NOT NULL DEFAULT '',
    approver    VARCHAR(255) NOT NULL DEFAULT '',
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at  DATETIME(6) NULL,
    approved_at DATETIME(6) NULL,
    consumed_at DATETIME(6) NULL,
    KEY idx_theauth_tool_approvals_expires (expires_at)
);
