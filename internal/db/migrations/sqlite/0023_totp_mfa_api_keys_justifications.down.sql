DROP TABLE IF EXISTS security_governance_settings;
DROP INDEX IF EXISTS idx_api_keys_hash;
DROP TABLE IF EXISTS api_keys;

ALTER TABLE users DROP COLUMN totp_recovery_hashes;
ALTER TABLE users DROP COLUMN totp_enabled;
ALTER TABLE users DROP COLUMN totp_secret_encrypted;
