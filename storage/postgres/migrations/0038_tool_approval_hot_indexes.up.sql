-- 0038: two indexes on theauth_tool_approvals, each added after EXPLAIN ANALYZE showed the plan on
-- 500000 rows.
--
-- theauth_tool_approvals_pending_idx is a partial index over undecided approvals only. The overdue
-- sweep (ListOverdueToolApprovals) filters on those four NULL columns, but the old plan walked the
-- whole expires_at index, so its cost grew with every approval ever opened. The WHERE clause repeats
-- the sweep's own terms, which is what lets Postgres prove the index applies.
--
-- theauth_tool_approvals_created_idx serves the admin list (ORDER BY created_at DESC, id ASC with
-- a LIMIT), which scanned and sorted the table.
--
-- Mirrors sqlite 0041. MySQL has no partial indexes and is left alone.
CREATE INDEX IF NOT EXISTS theauth_tool_approvals_pending_idx ON theauth_tool_approvals (expires_at, id)
    WHERE approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL AND expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS theauth_tool_approvals_created_idx ON theauth_tool_approvals (created_at DESC, id ASC);
