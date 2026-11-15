ALTER TABLE msi_apps DROP COLUMN winget_arch;
ALTER TABLE msi_apps DROP COLUMN winget_package_id;
ALTER TABLE device_app_installs DROP COLUMN installed_product_code;
ALTER TABLE device_app_installs DROP COLUMN installed_version;
DROP INDEX IF EXISTS idx_device_software_inventory_device;
DROP TABLE IF EXISTS device_software_inventory;
