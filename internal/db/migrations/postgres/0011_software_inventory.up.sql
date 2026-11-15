-- Agentless endpoint software inventory & live installed version tracking
CREATE TABLE IF NOT EXISTS device_software_inventory (
    device_id        TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    app_key          TEXT NOT NULL,
    name             TEXT NOT NULL,
    publisher        TEXT NOT NULL DEFAULT '',
    version          TEXT NOT NULL DEFAULT '',
    source           TEXT NOT NULL DEFAULT 'win32',
    product_code     TEXT NOT NULL DEFAULT '',
    upgrade_code     TEXT NOT NULL DEFAULT '',
    install_date     TEXT NOT NULL DEFAULT '',
    install_location TEXT NOT NULL DEFAULT '',
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, app_key)
);

CREATE INDEX IF NOT EXISTS idx_device_software_inventory_device
    ON device_software_inventory(device_id);

ALTER TABLE device_app_installs ADD COLUMN installed_version TEXT NOT NULL DEFAULT '';
ALTER TABLE device_app_installs ADD COLUMN installed_product_code TEXT NOT NULL DEFAULT '';

ALTER TABLE msi_apps ADD COLUMN winget_package_id TEXT NOT NULL DEFAULT '';
ALTER TABLE msi_apps ADD COLUMN winget_arch TEXT NOT NULL DEFAULT '';
