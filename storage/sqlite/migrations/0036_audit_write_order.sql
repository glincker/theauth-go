-- 0036: audit write order. recorded_at_us is a per-chain strictly increasing
-- microsecond stamp assigned by the writer inside the chained append, and
-- event is the shared event name (NULL when the action has none). Neither
-- column is part of the chain hash, so chains written before this migration
-- keep verifying. Mirrors postgres 0032 and mysql 0031.
-- SQLite cannot add a column with an expression default, so both columns are
-- plain nullable columns and a trigger stamps rows written by an older binary.
ALTER TABLE theauth_audit_events ADD COLUMN recorded_at_us INTEGER;
ALTER TABLE theauth_audit_events ADD COLUMN event TEXT;

-- created_at is stored in microseconds, so the backfill is a straight copy.
UPDATE theauth_audit_events SET recorded_at_us = created_at WHERE recorded_at_us IS NULL;

-- Backfill the event from the documented action mapping. Actions that do not
-- map stay NULL.
UPDATE theauth_audit_events SET event = CASE action
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

-- Rows inserted by a binary that predates this migration carry no stamp, so
-- keyset paging would skip them. Default the stamp to created_at.
CREATE TRIGGER IF NOT EXISTS theauth_audit_recorded_default AFTER INSERT ON theauth_audit_events
WHEN NEW.recorded_at_us IS NULL
BEGIN
    UPDATE theauth_audit_events SET recorded_at_us = NEW.created_at WHERE id = NEW.id;
END;

-- Keyset paging indexes, global, per organization and per event.
CREATE INDEX IF NOT EXISTS theauth_audit_recorded_idx ON theauth_audit_events (recorded_at_us, id);
CREATE INDEX IF NOT EXISTS theauth_audit_org_recorded_idx ON theauth_audit_events (organization_id, recorded_at_us, id);
CREATE INDEX IF NOT EXISTS theauth_audit_event_recorded_idx ON theauth_audit_events (event, recorded_at_us, id);
