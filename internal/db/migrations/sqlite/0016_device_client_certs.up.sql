-- Milestone 15: Per-Device X.509 Client Certificate Push (PFXCertInstall CSP) & EAP-TLS Wi-Fi

ALTER TABLE network_pki_profiles ADD COLUMN client_cert_subject_template TEXT NOT NULL DEFAULT 'CN={{device_name}}';
ALTER TABLE network_pki_profiles ADD COLUMN client_cert_validity_days INTEGER NOT NULL DEFAULT 365;
ALTER TABLE network_pki_profiles ADD COLUMN client_cert_exportable INTEGER NOT NULL DEFAULT 0;
ALTER TABLE network_pki_profiles ADD COLUMN client_cert_key_location INTEGER NOT NULL DEFAULT 3;
ALTER TABLE network_pki_profiles ADD COLUMN wifi_eap_server_names TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS device_issued_client_certs (
    device_id              TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    profile_id             TEXT NOT NULL REFERENCES network_pki_profiles(id) ON DELETE CASCADE,
    thumbprint             TEXT NOT NULL,
    serial_number          TEXT NOT NULL,
    subject                TEXT NOT NULL,
    not_before             DATETIME NOT NULL,
    not_after              DATETIME NOT NULL,
    pfx_b64_encrypted      TEXT NOT NULL,
    pfx_password_encrypted TEXT NOT NULL,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, profile_id)
);
