ALTER TABLE devices DROP COLUMN retired_at;
ALTER TABLE devices DROP COLUMN pending_hostname;
ALTER TABLE devices DROP COLUMN enrollment_state;

ALTER TABLE device_groups DROP COLUMN dynamic_rules_json;
ALTER TABLE device_groups DROP COLUMN match_mode;
ALTER TABLE device_groups DROP COLUMN is_dynamic;
