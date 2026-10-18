-- 0032: audit write order. recorded_at_us is a per-chain strictly increasing
-- microsecond stamp assigned by the writer inside the chained append, and
-- event is the shared event name (NULL when the action has none). Neither
-- column is part of the chain hash, so chains written before this migration
-- keep verifying. Mirrors mysql 0031 and sqlite 0036.
ALTER TABLE audit_events
    ADD COLUMN recorded_at_us bigint
        DEFAULT (floor(extract(epoch FROM clock_timestamp()) * 1000000))::bigint,
    ADD COLUMN event text;

-- Backfill the stamp from created_at in microseconds. The column default stamped
-- existing rows with the migration time, so every row is overwritten.
UPDATE audit_events
   SET recorded_at_us = floor(extract(epoch FROM created_at) * 1000000)::bigint
 WHERE recorded_at_us IS DISTINCT FROM floor(extract(epoch FROM created_at) * 1000000)::bigint;

-- Backfill the event from the documented action mapping. Actions that do not
-- map stay NULL.
UPDATE audit_events SET event = CASE action
    WHEN 'agent.authorize' THEN 'authorize'
    WHEN 'agent.authorize_denied' THEN 'authorize'
    WHEN 'agent.token_minted' THEN 'authorize.token'
    WHEN 'agent.token_denied' THEN 'authorize.token'
    WHEN 'policy.decision' THEN 'policy.evaluate'
    WHEN 'delegation.granted' THEN 'delegation.create'
    WHEN 'delegation.revoked' THEN 'delegation.revoke'
    WHEN 'agent.created' THEN 'agent.create'
    WHEN 'agent.revoked' THEN 'agent.revoke'
    WHEN 'agent.cascade.revoked' THEN 'agent.cascade.revoked'
    WHEN 'approval.request' THEN 'approval.request'
    WHEN 'tool_approval.approved' THEN 'approval.approve'
    WHEN 'tool_approval.denied' THEN 'approval.deny'
    WHEN 'vault.token.issued' THEN 'vault.read'
    WHEN 'audit.events_dropped' THEN 'audit.write_failed'
END
WHERE event IS NULL;

-- Highest stamp issued per chain, read under the head row lock by the writer.
ALTER TABLE theauth_audit_chain_heads ADD COLUMN recorded_at_us bigint NOT NULL DEFAULT 0;
UPDATE theauth_audit_chain_heads h
   SET recorded_at_us = COALESCE((SELECT max(e.recorded_at_us) FROM audit_events e WHERE e.chain_key = h.chain_key), 0)
 WHERE h.recorded_at_us = 0;

-- Keyset paging indexes, global, per organization and per event.
CREATE INDEX idx_audit_recorded ON audit_events (recorded_at_us, id);
CREATE INDEX idx_audit_org_recorded ON audit_events (organization_id, recorded_at_us, id);
CREATE INDEX idx_audit_event_recorded ON audit_events (event, recorded_at_us, id);
