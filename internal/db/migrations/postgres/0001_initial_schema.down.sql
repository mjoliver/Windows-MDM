-- 0001_initial_schema.down.sql
-- Rollback initial schema

DROP INDEX IF EXISTS idx_policy_catalog_csp;
DROP INDEX IF EXISTS idx_audit_log_created;
DROP INDEX IF EXISTS idx_compliance_device;
DROP INDEX IF EXISTS idx_command_queue_device_status;
DROP INDEX IF EXISTS idx_certificates_device;
DROP INDEX IF EXISTS idx_certificates_thumbprint;
DROP INDEX IF EXISTS idx_devices_active;
DROP INDEX IF EXISTS idx_devices_hardware_id;

DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS compliance_records;
DROP TABLE IF EXISTS command_queue;
DROP TABLE IF EXISTS group_profiles;
DROP TABLE IF EXISTS device_group_members;
DROP TABLE IF EXISTS device_groups;
DROP TABLE IF EXISTS profile_settings;
DROP TABLE IF EXISTS profiles;
DROP TABLE IF EXISTS policy_catalog;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS users;
