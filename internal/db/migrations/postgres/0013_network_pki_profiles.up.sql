-- Milestone 12: Agentless Enterprise Wi-Fi, VPNv2 & Root/Intermediate CA Certificate Provisioning

CREATE TABLE IF NOT EXISTS network_pki_profiles (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    profile_type       TEXT NOT NULL,

    cert_thumbprint    TEXT NOT NULL DEFAULT '',
    cert_subject       TEXT NOT NULL DEFAULT '',
    cert_not_after     TIMESTAMPTZ,
    cert_der_b64       TEXT NOT NULL DEFAULT '',

    wifi_ssid          TEXT NOT NULL DEFAULT '',
    wifi_security      TEXT NOT NULL DEFAULT 'WPA2PSK',
    wifi_auto_connect  INTEGER NOT NULL DEFAULT 1,
    wifi_hidden        INTEGER NOT NULL DEFAULT 0,
    wifi_psk_encrypted TEXT NOT NULL DEFAULT '',

    vpn_server          TEXT NOT NULL DEFAULT '',
    vpn_protocol        TEXT NOT NULL DEFAULT 'IKEv2',
    vpn_auth_method     TEXT NOT NULL DEFAULT 'Eap',
    vpn_split_tunnel    INTEGER NOT NULL DEFAULT 1,
    vpn_always_on       INTEGER NOT NULL DEFAULT 0,
    vpn_trusted_network TEXT NOT NULL DEFAULT '',

    target_all_devices INTEGER NOT NULL DEFAULT 1,
    created_by         TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS group_network_pki_profiles (
    group_id   TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    profile_id TEXT NOT NULL REFERENCES network_pki_profiles(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, profile_id)
);

CREATE TABLE IF NOT EXISTS device_network_pki_state (
    device_id      TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    profile_id     TEXT NOT NULL,
    profile_name   TEXT NOT NULL DEFAULT '',
    profile_type   TEXT NOT NULL,
    delete_oma_uri TEXT NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, profile_id)
);
