-- 0017: webauthn credential backup-eligible / backup-state flags.
--
-- go-webauthn's login validation rejects an assertion whose BE flag differs
-- from the stored credential. Synced passkeys (iCloud Keychain, Google
-- Password Manager, etc.) report BE=1, but before this column existed the
-- library never persisted the flag, so it read back as false and every
-- synced-passkey login failed with a generic "verification failed".
--
-- Both columns are genuinely nullable (no DEFAULT): NULL means "never
-- recorded" for a credential registered before this migration, which the
-- login path reconciles via trust-on-first-use. That is deliberately
-- distinct from a non-null false (a genuine non-backup-eligible credential
-- registered after the fix), so we must NOT use NOT NULL DEFAULT false here.

ALTER TABLE webauthn_credentials
    ADD COLUMN backup_eligible boolean,
    ADD COLUMN backup_state    boolean;
