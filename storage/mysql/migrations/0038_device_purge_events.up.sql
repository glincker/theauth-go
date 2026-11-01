-- 0038: device cache purge events for iot/mqttauth replicas. UP ONLY, like every file in this
-- directory. MySQL has no LISTEN and NOTIFY, so mysql.PurgeBroadcaster publishes by inserting a
-- row and every replica polls for rows newer than its cursor. Rows are short lived: subscribers
-- delete rows older than the retention window. An empty device_id means purge everything.
CREATE TABLE IF NOT EXISTS theauth_device_purge_events (
    id         BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    device_id  VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_device_purge_events_created (created_at)
);
