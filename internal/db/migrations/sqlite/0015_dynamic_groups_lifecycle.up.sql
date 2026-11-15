-- Milestone 14: Dynamic Smart Groups, Remote Hostname Rename & Clean MDM Retire

ALTER TABLE device_groups ADD COLUMN is_dynamic INTEGER NOT NULL DEFAULT 0;
ALTER TABLE device_groups ADD COLUMN match_mode TEXT NOT NULL DEFAULT 'all';
ALTER TABLE device_groups ADD COLUMN dynamic_rules_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE devices ADD COLUMN enrollment_state TEXT NOT NULL DEFAULT 'enrolled';
ALTER TABLE devices ADD COLUMN pending_hostname TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN retired_at DATETIME;
