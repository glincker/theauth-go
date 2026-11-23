-- 0034: approval decisions for guarded agent tool calls. opened_by feeds the four-eyes check,
-- denied_by and denied_at record a human denial, expired_at records the first time an overdue
-- request was noticed (so the expiry is audited once), and arguments_hash binds a request to the
-- arguments the approver saw (hex SHA-256, empty for rows opened before this migration).
ALTER TABLE theauth_tool_approvals ADD COLUMN IF NOT EXISTS opened_by text NOT NULL DEFAULT '';
ALTER TABLE theauth_tool_approvals ADD COLUMN IF NOT EXISTS denied_by text NOT NULL DEFAULT '';
ALTER TABLE theauth_tool_approvals ADD COLUMN IF NOT EXISTS denied_at timestamptz;
ALTER TABLE theauth_tool_approvals ADD COLUMN IF NOT EXISTS expired_at timestamptz;
ALTER TABLE theauth_tool_approvals ADD COLUMN IF NOT EXISTS arguments_hash text NOT NULL DEFAULT '';
