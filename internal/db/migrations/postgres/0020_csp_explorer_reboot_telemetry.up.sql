-- 0020_csp_explorer_reboot_telemetry.up.sql
-- Milestone 19: Live CSP Explorer query history + RebootRequired & WindowsLicensing/Edition telemetry

ALTER TABLE device_posture ADD COLUMN reboot_required INTEGER;
ALTER TABLE device_posture ADD COLUMN windows_edition INTEGER;
ALTER TABLE device_posture ADD COLUMN local_time TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS device_csp_queries (
    id           TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    queue_id     INTEGER,
    label        TEXT NOT NULL DEFAULT '',
    oma_uri      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    result_code  TEXT NOT NULL DEFAULT '',
    result_data  TEXT NOT NULL DEFAULT '',
    queried_by   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_device_csp_queries_device ON device_csp_queries(device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_csp_queries_queue ON device_csp_queries(queue_id);
