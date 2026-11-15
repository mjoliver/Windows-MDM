-- Agentless Ephemeral Local Administrator (Cloud LAPS) policy & AES-256-GCM vault
CREATE TABLE IF NOT EXISTS laps_policies (
    id                          TEXT PRIMARY KEY,
    enabled                     INTEGER NOT NULL DEFAULT 0,
    account_prefix              TEXT NOT NULL DEFAULT 'lzadm',
    password_length             INTEGER NOT NULL DEFAULT 20,
    rotation_days               INTEGER NOT NULL DEFAULT 14,
    rotate_after_reveal_minutes INTEGER NOT NULL DEFAULT 240,
    target_all_devices          INTEGER NOT NULL DEFAULT 1,
    updated_by                  TEXT NOT NULL DEFAULT '',
    updated_at                  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS group_laps_policies (
    group_id  TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    policy_id TEXT NOT NULL REFERENCES laps_policies(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, policy_id)
);

CREATE TABLE IF NOT EXISTS device_local_admins (
    device_id                   TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    active_account              TEXT NOT NULL DEFAULT '',
    active_password_encrypted   TEXT NOT NULL DEFAULT '',
    previous_account            TEXT NOT NULL DEFAULT '',
    previous_password_encrypted TEXT NOT NULL DEFAULT '',
    retired_accounts            TEXT NOT NULL DEFAULT '',
    pending_account             TEXT NOT NULL DEFAULT '',
    pending_password_encrypted  TEXT NOT NULL DEFAULT '',
    pending_queue_id            INTEGER NOT NULL DEFAULT 0,
    status                      TEXT NOT NULL DEFAULT 'unconfigured',
    last_error                  TEXT NOT NULL DEFAULT '',
    last_rotated_at             DATETIME,
    expires_at                  DATETIME,
    updated_at                  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
