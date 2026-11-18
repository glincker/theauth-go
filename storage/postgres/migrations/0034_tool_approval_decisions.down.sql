ALTER TABLE theauth_tool_approvals DROP COLUMN IF EXISTS arguments_hash;
ALTER TABLE theauth_tool_approvals DROP COLUMN IF EXISTS expired_at;
ALTER TABLE theauth_tool_approvals DROP COLUMN IF EXISTS denied_at;
ALTER TABLE theauth_tool_approvals DROP COLUMN IF EXISTS denied_by;
ALTER TABLE theauth_tool_approvals DROP COLUMN IF EXISTS opened_by;
