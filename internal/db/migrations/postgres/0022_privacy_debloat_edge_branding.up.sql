-- 0022_privacy_debloat_edge_branding.up.sql
-- Milestone 21: Windows 11 Privacy/Debloat, Corporate Branding & Microsoft Edge Security Baseline CSP

CREATE TABLE IF NOT EXISTS desktop_experience_policies (
    id                          TEXT PRIMARY KEY,
    enabled                     INTEGER NOT NULL DEFAULT 0,
    telemetry_level             INTEGER NOT NULL DEFAULT 1,
    disable_advertising_id      INTEGER NOT NULL DEFAULT 1,
    block_tailored_experiences  INTEGER NOT NULL DEFAULT 1,
    disable_widgets_news        INTEGER NOT NULL DEFAULT 1,
    edge_smartscreen_enabled    INTEGER NOT NULL DEFAULT 1,
    edge_prevent_ss_override    INTEGER NOT NULL DEFAULT 1,
    edge_smartscreen_pua        INTEGER NOT NULL DEFAULT 1,
    edge_block_password_manager INTEGER NOT NULL DEFAULT 0,
    edge_typosquatting_checker  INTEGER NOT NULL DEFAULT 1,
    desktop_wallpaper_url       TEXT NOT NULL DEFAULT '',
    lockscreen_image_url        TEXT NOT NULL DEFAULT '',
    target_all_devices          INTEGER NOT NULL DEFAULT 1,
    updated_by                  TEXT NOT NULL DEFAULT '',
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS group_desktop_experience_policies (
    policy_id TEXT NOT NULL REFERENCES desktop_experience_policies(id) ON DELETE CASCADE,
    group_id  TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (policy_id, group_id)
);

CREATE TABLE IF NOT EXISTS device_desktop_experience_state (
    device_id          TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    enforced           INTEGER NOT NULL DEFAULT 0,
    branding_enforced  INTEGER NOT NULL DEFAULT 0,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
