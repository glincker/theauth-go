-- 0039: attestation state on the device record. attestation_claims holds the JSON claims a verifier
-- proved at enrollment (securityLevel, verifiedBootState, appId and so on), or the empty string for a
-- device enrolled without hardware evidence. app_attest_counter is the highest Apple App Attest
-- assertion counter accepted for the device key, advanced by one conditional UPDATE.
ALTER TABLE iot_devices ADD COLUMN IF NOT EXISTS attestation_claims text NOT NULL DEFAULT '';
ALTER TABLE iot_devices ADD COLUMN IF NOT EXISTS app_attest_counter bigint NOT NULL DEFAULT 0;
