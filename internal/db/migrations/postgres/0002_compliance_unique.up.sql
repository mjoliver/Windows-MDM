-- Postgres already enforces UNIQUE(device_id, catalog_id) via 0001; this index
-- is created IF NOT EXISTS only to keep the migration set aligned across drivers.
CREATE UNIQUE INDEX IF NOT EXISTS ux_compliance_records_device_catalog
    ON compliance_records(device_id, catalog_id);
