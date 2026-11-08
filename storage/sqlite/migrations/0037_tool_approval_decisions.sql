-- 0037: approval decisions for guarded agent tool calls. opened_by feeds the four-eyes check,
-- denied_by and denied_at record a human denial, expired_at records the first time an overdue
-- request was noticed (so the expiry is audited once), and arguments_hash binds a request to the
-- arguments the approver saw (hex SHA-256, empty for rows opened before this migration). Mirrors
-- postgres 0034 and mysql 0032. Times are Unix microseconds.
ALTER TABLE theauth_tool_approvals ADD COLUMN opened_by TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_tool_approvals ADD COLUMN denied_by TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_tool_approvals ADD COLUMN denied_at INTEGER;
ALTER TABLE theauth_tool_approvals ADD COLUMN expired_at INTEGER;
ALTER TABLE theauth_tool_approvals ADD COLUMN arguments_hash TEXT NOT NULL DEFAULT '';
