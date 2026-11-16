-- Milestone 16: Defender Attack Surface Reduction (ASR) Rules & SmartScreen Hardening CSP

CREATE TABLE IF NOT EXISTS endpoint_hardening_policies (
    id                             TEXT PRIMARY KEY,
    enabled                        INTEGER NOT NULL DEFAULT 0,
    asr_rules_json                 TEXT NOT NULL DEFAULT '{}',
    enable_smartscreen_shell       INTEGER NOT NULL DEFAULT 1,
    prevent_smartscreen_override   INTEGER NOT NULL DEFAULT 1,
    app_install_control            INTEGER NOT NULL DEFAULT 0, -- 0=Anywhere, 1=StoreOnly, 2=PreferStore, 3=WarnNonStore
    submit_samples_consent         INTEGER NOT NULL DEFAULT 1, -- 0=Prompt, 1=SafeSamples, 2=Never, 3=AllSamples
    disable_local_admin_merge      INTEGER NOT NULL DEFAULT 1,
    target_all_devices             INTEGER NOT NULL DEFAULT 1,
    updated_by                     TEXT NOT NULL DEFAULT '',
    updated_at                     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS group_endpoint_hardening_policies (
    group_id   TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    policy_id  TEXT NOT NULL REFERENCES endpoint_hardening_policies(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, policy_id)
);

CREATE TABLE IF NOT EXISTS device_endpoint_hardening_state (
    device_id          TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    enforced           INTEGER NOT NULL DEFAULT 0,
    active_asr_count   INTEGER NOT NULL DEFAULT 0,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
