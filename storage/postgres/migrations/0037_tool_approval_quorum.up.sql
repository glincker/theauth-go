-- 0037: quorum (two person) approvals for guarded agent tool calls. required_approvals is how many
-- distinct approvers a request needs (1 is the ordinary single approver flow, so every existing row
-- keeps its behavior). theauth_tool_approval_votes holds one row per approver who approved; the
-- primary key on (approval_id, approver) is what counts each approver once under concurrent
-- decisions. Mirrors sqlite 0040 and mysql 0037.
ALTER TABLE theauth_tool_approvals ADD COLUMN IF NOT EXISTS required_approvals integer NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS theauth_tool_approval_votes (
    approval_id text NOT NULL,
    approver    text NOT NULL,
    voted_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (approval_id, approver)
);
