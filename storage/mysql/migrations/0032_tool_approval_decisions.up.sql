-- 0032: approval decisions for guarded agent tool calls. UP ONLY, like every file in this
-- directory. Mirrors postgres 0034 and sqlite 0037. opened_by feeds the four-eyes check,
-- denied_by and denied_at record a human denial, expired_at records the first time an overdue
-- request was noticed so the expiry is audited once, and arguments_hash binds a request to the
-- arguments the approver saw (hex SHA-256, empty for rows opened before this migration).
ALTER TABLE theauth_tool_approvals
    ADD COLUMN opened_by VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN denied_by VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN denied_at DATETIME(6) NULL,
    ADD COLUMN expired_at DATETIME(6) NULL,
    ADD COLUMN arguments_hash VARCHAR(64) NOT NULL DEFAULT '';
