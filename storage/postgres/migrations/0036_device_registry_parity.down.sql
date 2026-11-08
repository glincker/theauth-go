DROP INDEX IF EXISTS idx_iot_devices_thumbprint;
ALTER TABLE device_join_tokens DROP COLUMN IF EXISTS uses;
ALTER TABLE device_join_tokens DROP COLUMN IF EXISTS max_uses;
