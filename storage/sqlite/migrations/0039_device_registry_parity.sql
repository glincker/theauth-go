-- 0039: device registry parity. Join tokens gain a use counter so one token can enroll many
-- devices (bulk enrollment), and theauth_iot_devices gets an index for key thumbprint lookups.
-- Existing redeemed tokens count as one use of one.
ALTER TABLE theauth_device_join_tokens ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 1;
ALTER TABLE theauth_device_join_tokens ADD COLUMN uses INTEGER NOT NULL DEFAULT 0;
UPDATE theauth_device_join_tokens SET uses = 1 WHERE redeemed_at IS NOT NULL AND uses = 0;
CREATE INDEX IF NOT EXISTS theauth_iot_devices_thumbprint_idx ON theauth_iot_devices (key_thumbprint, created_at DESC);
