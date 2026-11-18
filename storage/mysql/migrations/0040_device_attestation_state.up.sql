-- 0040: attestation state on the device record. attestation_claims holds the JSON claims a verifier
-- proved at enrollment (securityLevel, verifiedBootState, appId and so on), NULL for a device enrolled
-- without hardware evidence (TEXT cannot carry a default on 8.0.12 and older). app_attest_counter is
-- the highest Apple App Attest assertion counter accepted for the device key, advanced by one
-- conditional UPDATE.
ALTER TABLE iot_devices ADD COLUMN attestation_claims TEXT NULL;
ALTER TABLE iot_devices ADD COLUMN app_attest_counter BIGINT UNSIGNED NOT NULL DEFAULT 0;
