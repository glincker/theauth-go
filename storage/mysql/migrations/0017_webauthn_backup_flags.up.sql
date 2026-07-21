-- 0017: WebAuthn credential backup-eligible / backup-state flags.
--
-- go-webauthn's login validation rejects an assertion whose BE flag differs
-- from the stored credential. Synced passkeys report BE=1, but before this
-- column existed the flag was never persisted, so it read back as false and
-- every synced-passkey login failed.
--
-- Both columns are genuinely nullable (no DEFAULT): NULL means "never
-- recorded" (a pre-fix credential, reconciled at login via trust-on-first
-- -use) and is distinct from a non-null false. Do NOT use NOT NULL DEFAULT.

ALTER TABLE webauthn_credentials
    ADD COLUMN backup_eligible TINYINT(1) NULL,
    ADD COLUMN backup_state    TINYINT(1) NULL;
