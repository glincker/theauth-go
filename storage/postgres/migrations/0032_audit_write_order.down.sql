DROP INDEX IF EXISTS idx_audit_event_recorded;
DROP INDEX IF EXISTS idx_audit_org_recorded;
DROP INDEX IF EXISTS idx_audit_recorded;
ALTER TABLE theauth_audit_chain_heads DROP COLUMN IF EXISTS recorded_at_us;
ALTER TABLE audit_events
    DROP COLUMN IF EXISTS event,
    DROP COLUMN IF EXISTS recorded_at_us;
