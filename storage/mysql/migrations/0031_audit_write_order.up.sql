-- 0031: audit write order (recorded_at_us) and shared event name (event).
-- Mirrors postgres 0032 and sqlite 0036. UP ONLY, like every file in this directory.
-- Neither column is part of the audit chain hash, so chains written before this
-- migration keep verifying and no existing row is rewritten in a way the hash sees.
--
-- recorded_at_us: write order stamp in microseconds since the Unix epoch, assigned by the
-- store inside the chained append (strictly increasing per chain key). Old rows are
-- backfilled from created_at. DATETIME(6) values are written and read as UTC by this
-- package, so the backfill reads them as UTC and never depends on the session time zone.
-- The column default covers an older binary that still inserts without the column during a
-- rolling deploy. It is an expression default (MySQL 8.0.13 or later) built on UTC_TIMESTAMP
-- so it does not depend on the session time zone either.
--
-- event: shared event name, NULL when the action has none (open vocabulary). VARCHAR(255)
-- like the action column, not VARCHAR(64): writers may set their own names and a strict
-- mode insert must not fail on length. Still indexable: 255 chars is at most 1020 bytes in
-- utf8mb4, plus 8 for recorded_at_us and 16 for id, well under the 3072 byte InnoDB key
-- limit. The organization index is 16 + 8 + 16 bytes.
--
-- The column is added without a default first, then backfilled for every row, then given its
-- default: ADD COLUMN with an expression default would stamp existing rows with the migration
-- time instead of their creation time.
--
-- Large tables: the two UPDATE statements and the index builds scan audit_events once each.
-- Operators with very large tables can run the backfill in batches and build the indexes with
-- an online tool before Migrate runs.
ALTER TABLE audit_events
    ADD COLUMN recorded_at_us BIGINT NULL,
    ADD COLUMN event          VARCHAR(255) NULL;

UPDATE audit_events
   SET recorded_at_us = TIMESTAMPDIFF(MICROSECOND, '1970-01-01 00:00:00', created_at);

UPDATE audit_events SET event = CASE action
    WHEN 'agent.authorize'        THEN 'authorize'
    WHEN 'agent.authorize_denied' THEN 'authorize'
    WHEN 'agent.token_minted'     THEN 'authorize.token'
    WHEN 'agent.token_denied'     THEN 'authorize.token'
    WHEN 'policy.decision'        THEN 'policy.evaluate'
    WHEN 'delegation.granted'     THEN 'delegation.create'
    WHEN 'delegation.revoked'     THEN 'delegation.revoke'
    WHEN 'agent.created'          THEN 'agent.create'
    WHEN 'agent.revoked'          THEN 'agent.revoke'
    WHEN 'agent.cascade.revoked'  THEN 'agent.cascade.revoked'
    WHEN 'approval.request'       THEN 'approval.request'
    WHEN 'tool_approval.approved' THEN 'approval.approve'
    WHEN 'tool_approval.denied'   THEN 'approval.deny'
    WHEN 'vault.token.issued'     THEN 'vault.read'
    WHEN 'audit.events_dropped'   THEN 'audit.write_failed'
    END
 WHERE event IS NULL AND action IN (
    'agent.authorize', 'agent.authorize_denied', 'agent.token_minted', 'agent.token_denied',
    'policy.decision', 'delegation.granted', 'delegation.revoked', 'agent.created',
    'agent.revoked', 'agent.cascade.revoked', 'approval.request', 'tool_approval.approved',
    'tool_approval.denied', 'vault.token.issued', 'audit.events_dropped');

ALTER TABLE audit_events
    ALTER COLUMN recorded_at_us SET DEFAULT (TIMESTAMPDIFF(MICROSECOND, '1970-01-01 00:00:00', UTC_TIMESTAMP(6)));

-- Highest stamp issued per chain. The append already locks this row, so it is the floor for
-- the next stamp: a stalled clock or another process that wrote ahead cannot repeat a stamp.
ALTER TABLE theauth_audit_chain_heads ADD COLUMN recorded_at_us BIGINT NOT NULL DEFAULT 0;

UPDATE theauth_audit_chain_heads h
   SET h.recorded_at_us = COALESCE(
       (SELECT MAX(a.recorded_at_us) FROM audit_events a WHERE a.chain_key = h.chain_key), 0);

CREATE INDEX idx_audit_recorded ON audit_events (recorded_at_us, id);

CREATE INDEX idx_audit_org_recorded ON audit_events (organization_id, recorded_at_us, id);

CREATE INDEX idx_audit_event_recorded ON audit_events (event, recorded_at_us, id);
