-- Hardware inventory and Windows security posture telemetry collected via OMA-DM
CREATE TABLE IF NOT EXISTS device_posture (
    device_id          TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    total_ram_mb       INTEGER,
    total_storage_mb   INTEGER,
    free_storage_mb    INTEGER,
    bios_version       TEXT,
    os_platform        TEXT,
    tpm_version        TEXT,
    secure_boot_state  INTEGER,
    encryption_status  INTEGER,
    antivirus_status   INTEGER,
    firewall_status    INTEGER,
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
