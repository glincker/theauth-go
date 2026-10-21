-- 0036: device registry parity. Join tokens gain a use counter so one token can enroll many
-- devices (bulk enrollment), and iot_devices gets an index for key thumbprint lookups. Existing
-- redeemed tokens count as one use of one.
ALTER TABLE device_join_tokens ADD COLUMN IF NOT EXISTS max_uses integer NOT NULL DEFAULT 1;
ALTER TABLE device_join_tokens ADD COLUMN IF NOT EXISTS uses integer NOT NULL DEFAULT 0;
UPDATE device_join_tokens SET uses = 1 WHERE redeemed_at IS NOT NULL AND uses = 0;
CREATE INDEX IF NOT EXISTS idx_iot_devices_thumbprint ON iot_devices (key_thumbprint, created_at DESC);
