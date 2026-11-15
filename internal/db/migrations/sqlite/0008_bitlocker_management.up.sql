-- BitLocker policy management and AES-256-GCM encrypted recovery key escrow
CREATE TABLE IF NOT EXISTS bitlocker_policies (
    id                        TEXT PRIMARY KEY,
    enabled                   INTEGER NOT NULL DEFAULT 0,
    require_device_encryption INTEGER NOT NULL DEFAULT 1,
    silent_encryption         INTEGER NOT NULL DEFAULT 1,
    allow_standard_user       INTEGER NOT NULL DEFAULT 1,
    os_drive_cipher           INTEGER NOT NULL DEFAULT 7,
    fixed_drive_cipher        INTEGER NOT NULL DEFAULT 7,
    removable_drive_cipher    INTEGER NOT NULL DEFAULT 4,
    target_all_devices        INTEGER NOT NULL DEFAULT 1,
    updated_by                TEXT NOT NULL DEFAULT '',
    updated_at                DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS group_bitlocker_policies (
    group_id  TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    policy_id TEXT NOT NULL REFERENCES bitlocker_policies(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, policy_id)
);

CREATE TABLE IF NOT EXISTS device_bitlocker_state (
    device_id  TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    enforced   INTEGER NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_recovery_keys (
    id            TEXT PRIMARY KEY,
    device_id     TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    volume_letter TEXT NOT NULL DEFAULT 'C:',
    protector_id  TEXT NOT NULL,
    key_encrypted TEXT NOT NULL,
    key_hint      TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT 'admin_escrow',
    escrowed_by   TEXT NOT NULL DEFAULT '',
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (device_id, protector_id)
);
