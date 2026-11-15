-- Milestone 13: Agentless Device Lockdown, USB Removable Storage, DeviceLock & Kiosk CSPs

CREATE TABLE IF NOT EXISTS device_lockdown_policies (
    id                      TEXT PRIMARY KEY,
    enabled                 INTEGER NOT NULL DEFAULT 0,
    usb_storage_mode        TEXT NOT NULL DEFAULT 'allow', -- 'allow' | 'read_only' | 'block_all'
    require_password        INTEGER NOT NULL DEFAULT 1,
    min_password_length     INTEGER NOT NULL DEFAULT 8,
    alphanumeric_required   INTEGER NOT NULL DEFAULT 0,
    max_inactivity_minutes  INTEGER NOT NULL DEFAULT 15,
    max_failed_attempts     INTEGER NOT NULL DEFAULT 10,
    allow_camera            INTEGER NOT NULL DEFAULT 1,
    allow_bluetooth         INTEGER NOT NULL DEFAULT 1,
    kiosk_mode              TEXT NOT NULL DEFAULT 'none', -- 'none' | 'single_app'
    kiosk_account           TEXT NOT NULL DEFAULT 'KioskUser',
    kiosk_app_aumid         TEXT NOT NULL DEFAULT '',
    target_all_devices      INTEGER NOT NULL DEFAULT 1,
    updated_by              TEXT NOT NULL DEFAULT '',
    updated_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS group_device_lockdown_policies (
    group_id  TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    policy_id TEXT NOT NULL REFERENCES device_lockdown_policies(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, policy_id)
);

CREATE TABLE IF NOT EXISTS device_lockdown_state (
    device_id      TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    enforced       INTEGER NOT NULL DEFAULT 0,
    kiosk_enforced INTEGER NOT NULL DEFAULT 0,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
