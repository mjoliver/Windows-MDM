DROP INDEX IF EXISTS idx_device_csp_queries_queue;
DROP INDEX IF EXISTS idx_device_csp_queries_device;
DROP TABLE IF EXISTS device_csp_queries;

ALTER TABLE device_posture DROP COLUMN local_time;
ALTER TABLE device_posture DROP COLUMN windows_edition;
ALTER TABLE device_posture DROP COLUMN reboot_required;
