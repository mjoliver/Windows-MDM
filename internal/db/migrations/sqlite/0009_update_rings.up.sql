-- Windows Update Rings via Policy/Config/Update and Update CSPs
CREATE TABLE IF NOT EXISTS update_rings (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    description             TEXT NOT NULL DEFAULT '',
    allow_auto_update       INTEGER NOT NULL DEFAULT 2,
    quality_deferral_days   INTEGER NOT NULL DEFAULT 7,
    feature_deferral_days   INTEGER NOT NULL DEFAULT 30,
    active_hours_start      INTEGER NOT NULL DEFAULT 8,
    active_hours_end        INTEGER NOT NULL DEFAULT 17,
    quality_deadline_days   INTEGER NOT NULL DEFAULT 7,
    feature_deadline_days   INTEGER NOT NULL DEFAULT 14,
    grace_period_days       INTEGER NOT NULL DEFAULT 2,
    quality_pause_start     TEXT NOT NULL DEFAULT '',
    feature_pause_start     TEXT NOT NULL DEFAULT '',
    target_all_devices      INTEGER NOT NULL DEFAULT 0,
    priority                INTEGER NOT NULL DEFAULT 100,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS group_update_rings (
    group_id    TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    ring_id     TEXT NOT NULL REFERENCES update_rings(id) ON DELETE CASCADE,
    assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, ring_id)
);

CREATE TABLE IF NOT EXISTS device_update_status (
    device_id      TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    ring_id        TEXT,
    quality_paused INTEGER NOT NULL DEFAULT 0,
    feature_paused INTEGER NOT NULL DEFAULT 0,
    last_scan_time TEXT NOT NULL DEFAULT '',
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
