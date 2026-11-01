-- 0039: two indexes on theauth_tool_approvals, each added after EXPLAIN ANALYZE on MySQL 8.4 showed
-- the plan on 500000 rows. UP ONLY, like every file in this directory. Mirrors postgres 0038 and
-- sqlite 0041. The number follows 0038 (purge events); 0035 was never used on MySQL.
--
-- theauth_tool_approvals_pending_idx stands in for the partial index the other stores have. MySQL
-- cannot index only the undecided rows, so the four decision columns lead the key. The overdue
-- sweep (ListOverdueToolApprovals) tests all four with IS NULL, which MySQL treats as an equality
-- prefix, then ranges on expires_at and wants ORDER BY expires_at, id, which the tail of the key
-- delivers without a sort. Decided rows each get an entry too (a few more bytes per row), but they
-- sit under a different prefix and the sweep never walks them. Before: the sweep walked the whole
-- expires_at index, so its cost followed the number of approvals ever opened.
--
-- theauth_tool_approvals_created_idx serves the admin list (ORDER BY created_at DESC, id ASC with
-- a LIMIT), which scanned the table and sorted it. MySQL 8 keeps the descending key part.
CREATE INDEX theauth_tool_approvals_pending_idx ON theauth_tool_approvals
    (approved_at, consumed_at, denied_at, expired_at, expires_at, id);

CREATE INDEX theauth_tool_approvals_created_idx ON theauth_tool_approvals (created_at DESC, id ASC);
