-- 0010: audit log.
-- metadata stored as JSON. ip as VARCHAR(45) (covers IPv4 + IPv6).
-- Append-only table: no UPDATE or DELETE should be issued against it.

CREATE TABLE IF NOT EXISTS audit_events (
    id                BINARY(16) PRIMARY KEY,
    organization_id   BINARY(16),
    actor_user_id     BINARY(16),
    actor_session_id  BINARY(16),
    actor_agent_id    BINARY(16),
    action            VARCHAR(255) NOT NULL,
    target_type       VARCHAR(255),
    target_id         VARCHAR(255),
    metadata          JSON NOT NULL,
    ip                VARCHAR(45),
    user_agent        TEXT,
    created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_audit_org_created_at (organization_id, created_at),
    KEY idx_audit_actor_created_at (actor_user_id, created_at),
    KEY idx_audit_action_created_at (action, created_at),
    KEY idx_audit_events_actor_agent_id (actor_agent_id),
    CONSTRAINT fk_audit_events_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_events_user FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_events_session FOREIGN KEY (actor_session_id) REFERENCES sessions(id) ON DELETE SET NULL
);
