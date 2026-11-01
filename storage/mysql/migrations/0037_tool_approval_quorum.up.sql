-- 0037: quorum (two person) approvals for guarded agent tool calls. UP ONLY, like every file in
-- this directory. Mirrors postgres 0037 and sqlite 0040. required_approvals is how many distinct
-- approvers a request needs (1 is the ordinary single approver flow, so every existing row keeps
-- its behavior). theauth_tool_approval_votes holds one row per approver who approved; the primary
-- key on (approval_id, approver) is what counts each approver once under concurrent decisions.
ALTER TABLE theauth_tool_approvals
    ADD COLUMN required_approvals INT NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS theauth_tool_approval_votes (
    approval_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    approver    VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    voted_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (approval_id, approver)
);
