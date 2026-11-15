-- Milestone 11: Agentless Windows Defender Antivirus & Firewall CSP security baselines + custom firewall rules

CREATE TABLE IF NOT EXISTS endpoint_security_policies (
    id                         TEXT PRIMARY KEY,
    enabled                    INTEGER NOT NULL DEFAULT 0,
    allow_realtime_monitoring  INTEGER NOT NULL DEFAULT 1,
    allow_behavior_monitoring  INTEGER NOT NULL DEFAULT 1,
    allow_cloud_protection     INTEGER NOT NULL DEFAULT 1,
    cloud_block_level          INTEGER NOT NULL DEFAULT 2,
    pua_protection             INTEGER NOT NULL DEFAULT 1,
    enable_network_protection  INTEGER NOT NULL DEFAULT 1,
    check_sigs_before_scan     INTEGER NOT NULL DEFAULT 1,
    firewall_domain_enabled    INTEGER NOT NULL DEFAULT 1,
    firewall_private_enabled   INTEGER NOT NULL DEFAULT 1,
    firewall_public_enabled    INTEGER NOT NULL DEFAULT 1,
    block_inbound_domain       INTEGER NOT NULL DEFAULT 1,
    block_inbound_private      INTEGER NOT NULL DEFAULT 1,
    block_inbound_public       INTEGER NOT NULL DEFAULT 1,
    target_all_devices         INTEGER NOT NULL DEFAULT 1,
    updated_by                 TEXT NOT NULL DEFAULT '',
    updated_at                 DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS group_endpoint_security_policies (
    group_id  TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    policy_id TEXT NOT NULL REFERENCES endpoint_security_policies(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, policy_id)
);

CREATE TABLE IF NOT EXISTS device_security_baseline_state (
    device_id               TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    enforced                INTEGER NOT NULL DEFAULT 0,
    last_defender_action    TEXT NOT NULL DEFAULT '',
    last_defender_action_at DATETIME,
    updated_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    id                 TEXT PRIMARY KEY,
    rule_key           TEXT NOT NULL UNIQUE,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    direction          TEXT NOT NULL DEFAULT 'IN',
    action             INTEGER NOT NULL DEFAULT 0,
    protocol           INTEGER NOT NULL DEFAULT 6,
    local_port_ranges  TEXT NOT NULL DEFAULT '',
    remote_port_ranges TEXT NOT NULL DEFAULT '',
    profiles           INTEGER NOT NULL DEFAULT 7,
    enabled            INTEGER NOT NULL DEFAULT 1,
    target_all_devices INTEGER NOT NULL DEFAULT 1,
    created_by         TEXT NOT NULL DEFAULT '',
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS group_firewall_rules (
    group_id TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    rule_id  TEXT NOT NULL REFERENCES firewall_rules(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, rule_id)
);

CREATE TABLE IF NOT EXISTS device_firewall_rule_state (
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_key   TEXT NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, rule_key)
);
