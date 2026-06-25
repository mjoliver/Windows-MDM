-- The 0001 SQLite schema omitted the UNIQUE(device_id, catalog_id) constraint
-- that the Postgres schema has, so updateCompliance's
-- INSERT ... ON CONFLICT(device_id, catalog_id) failed on the default driver.
-- A unique index satisfies the ON CONFLICT target.
CREATE UNIQUE INDEX IF NOT EXISTS ux_compliance_records_device_catalog
    ON compliance_records(device_id, catalog_id);
