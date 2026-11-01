-- 0042: attestation state on the device record. attestation_claims holds the JSON claims a verifier
-- proved at enrollment (securityLevel, verifiedBootState, appId and so on), or the empty string for a
-- device enrolled without hardware evidence. app_attest_counter is the highest Apple App Attest
-- assertion counter accepted for the device key, advanced by one conditional UPDATE.
ALTER TABLE theauth_iot_devices ADD COLUMN attestation_claims TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_iot_devices ADD COLUMN app_attest_counter INTEGER NOT NULL DEFAULT 0;
