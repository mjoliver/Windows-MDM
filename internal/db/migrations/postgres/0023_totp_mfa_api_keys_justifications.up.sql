-- 0023_totp_mfa_api_keys_justifications.up.sql
-- Milestone 22: Admin TOTP MFA, Scoped Automation API Keys (lzak_...) & Audited Reveal Justifications

ALTER TABLE users ADD COLUMN totp_secret_encrypted TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_recovery_hashes TEXT NOT NULL DEFAULT '[]';

CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    key_prefix   TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    scope        TEXT NOT NULL DEFAULT 'read_only',
    created_by   TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked      INTEGER NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);

CREATE TABLE IF NOT EXISTS security_governance_settings (
    id                           TEXT PRIMARY KEY,
    require_reveal_justification INTEGER NOT NULL DEFAULT 0,
    updated_by                   TEXT NOT NULL DEFAULT '',
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
